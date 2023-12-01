# go_toa

借助fnqueue，拦截IP包，为连接的第一个ack添加toa，从而携带原始客户端IP和端口。

toa可以参考：[toa原理](https://cloud.tencent.com/document/product/608/14429)

使用例子参考：[例子](https://github.com/619561504/plow/tree/toa)

![image](https://github.com/619561504/go_toa/assets/14119716/b5d7f70a-1e68-4a59-84aa-1904dbc63fed)

编译及依赖：(DockerFile)[https://github.com/619561504/plow/blob/toa/Dockerfile]

