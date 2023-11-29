//go:build linux

/**
 * Created by wuhanjie on 2023/11/28 11:12
 */

package go_toa

import (
	"encoding/binary"
	"fmt"
	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/avast/retry-go/v4"
	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/patrickmn/go-cache"
	"github.com/sourcegraph/conc/pool"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	ruleSpecTemplate     = "-p tcp -m mark --mark %d -j NFQUEUE --queue-num 0"
	table                = "mangle"
	chain                = "POSTROUTING"
	optionType           = 200
	defaultMark          = 88
	defaultMaxGoroutines = 1
)

var (
	mu       sync.Mutex
	ruleSpec []string
	opt      options
)

type tcpOptions struct {
	v [6]byte
}

var (
	tcpOptionsPool = sync.Pool{
		New: func() interface{} {
			return &tcpOptions{}
		},
	}
	c = cache.New(1*time.Minute, 2*time.Minute)
)

type netFilter struct {
	q *netfilter.NFQueue
}

func newFilter() (*netFilter, error) {
	q, err := netfilter.NewNFQueue(0, 1000, netfilter.NF_DEFAULT_PACKET_SIZE)

	if err != nil {
		return nil, err
	}
	return &netFilter{q: q}, nil
}

func run(opts ...Option) error {

	for _, o := range opts {
		o(&opt)
	}

	if opt.mark == 0 {
		opt.mark = defaultMark
	}

	if opt.maxGoroutines == 0 {
		opt.maxGoroutines = defaultMaxGoroutines
	}

	ruleSpec = strings.Split(fmt.Sprintf(ruleSpecTemplate, opt.mark), " ")

	err := initIptables()
	if err != nil {
		return err
	}
	nf, err := newFilter()
	if err != nil {
		return err
	}

	go nf.Run()

	return nil
}

func dialWithRetry(addr string, clientIp string, clientPort int) (net.Conn, error) {
	return retry.DoWithData(func() (net.Conn, error) {
		return dial(addr, clientIp, clientPort)
	}, retry.Attempts(uint(opt.maxRetry)), retry.Delay(100*time.Millisecond))
}

func dial(addr string, clientIp string, clientPort int) (net.Conn, error) {
	lAddr, err := getAvailableAddr()

	if err != nil {
		return nil, err
	}
	port := lAddr.(*net.TCPAddr).Port

	err = newTcpOptions(port, net.ParseIP(clientIp), clientPort)

	if err != nil {
		return nil, err
	}

	dialer := net.Dialer{LocalAddr: lAddr}

	dialer.Control = func(network, address string, c syscall.RawConn) error {
		var syscallErr error

		err := c.Control(func(fd uintptr) {
			syscallErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if syscallErr != nil {
				return
			}
			syscallErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, opt.mark)
		})
		if syscallErr != nil {
			return syscallErr
		}
		return err
		// return nil
	}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	conn.(*net.TCPConn).SetLinger(0)

	return conn, nil
}

func (n *netFilter) Run() {

	goPool := pool.New().WithMaxGoroutines(opt.maxGoroutines)
	c := n.q.GetPackets()
	for {
		select {
		case pack := <-c:
			goPool.Go(func() {
				if ipLayer := pack.Packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
					ipv4 := ipLayer.(*layers.IPv4)

					if tcpLayer := pack.Packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
						tcp := tcpLayer.(*layers.TCP)

						sp := int(tcp.SrcPort)

						// fmt.Printf("%v,%v\n", sp, tcp)
						if v, ok := getTcpOptions(sp); ok && tcp.ACK {
							defer closeTcpOptions(sp)
							// fmt.Printf("%v,%v\n", sp, v)
							tcp.Options = append(tcp.Options, layers.TCPOption{
								OptionType:   optionType,
								OptionLength: uint8(len(v) + 2),
								OptionData:   v,
							})

							var options gopacket.SerializeOptions = gopacket.SerializeOptions{
								FixLengths:       true,
								ComputeChecksums: true,
							}
							buffer := gopacket.NewSerializeBuffer()
							err := tcp.SetNetworkLayerForChecksum(ipv4)

							if err != nil {
								fmt.Fprintf(os.Stderr, "SetNetworkLayerForChecksum err: %v\n", err)
								return
							}
							err = gopacket.SerializeLayers(buffer, options,
								ipv4,
								tcp,
								gopacket.Payload(tcp.Payload),
							)

							if err != nil {
								fmt.Fprintf(os.Stderr, "SerializeLayers err: %v\n", err)
								return
							}
							pack.SetVerdictWithPacket(netfilter.NF_ACCEPT, buffer.Bytes())

						} else {
							pack.SetVerdict(netfilter.NF_ACCEPT)
						}
					}
				} else {
					pack.SetVerdict(netfilter.NF_ACCEPT)
				}

			})
		}
	}
	goPool.Wait()
}

func initIptables() error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	err = ipt.AppendUnique(table, chain, ruleSpec...)
	if err != nil {
		return err
	}
	return nil
}

func clearIptables() error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	return ipt.DeleteIfExists(table, chain, ruleSpec...)
}

func getAvailableAddr() (net.Addr, error) {
	mu.Lock()
	defer mu.Unlock()
	l, err := net.ListenTCP("tcp", nil)
	if err != nil {
		return nil, err
	}
	defer l.Close()

	return l.Addr(), nil
}

func newTcpOptions(srcPort int, ip net.IP, port int) error {

	tcpOptions := tcpOptionsPool.Get().(*tcpOptions)
	binary.BigEndian.PutUint16(tcpOptions.v[:2], uint16(port))
	copy(tcpOptions.v[2:], ip.To4())
	c.SetDefault(strconv.Itoa(srcPort), tcpOptions)
	return nil
}

func getTcpOptions(srcPort int) ([]byte, bool) {
	k := strconv.Itoa(srcPort)
	if v, ok := c.Get(k); ok {
		o := v.(*tcpOptions)
		return o.v[:], ok
	}
	return nil, false
}

func closeTcpOptions(srcPort int) {
	k := strconv.Itoa(srcPort)

	if v, ok := c.Get(k); ok {
		c.Delete(k)
		defer tcpOptionsPool.Put(v)
	}
}

func close() error {
	return clearIptables()
}
