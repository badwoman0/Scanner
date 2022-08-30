package protocolScaner

import (
	"crypto/tls"
	"net"
	"strconv"
	"time"
)

func TcpConn(payload []byte, ip string, port int, timeout time.Duration) ([]byte, error) {
	portStr := strconv.Itoa(port)

	conn, err := net.DialTimeout("tcp", ip+":"+portStr, timeout) // 绑定服务端地址
	if err != nil {
		return []byte(""), err
	}
	defer conn.Close() // 关闭双向链接

	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	_, err = conn.Write([]byte(payload)) // 发送数据
	if err != nil {
		return []byte(""), err

	}
	buf := [1024]byte{}
	serverMsg, err := conn.Read(buf[:]) // 服务端返回的信息
	if err != nil {
		return []byte(""), err
	}
	return buf[:serverMsg], nil

}

func TcpConnSSL(payload []byte, ip string, port int, timeout time.Duration) ([]byte, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	portStr := strconv.Itoa(port)

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", ip+":"+portStr, conf)
	if err != nil {
		return []byte(""), err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(payload))
	if err != nil {
		return []byte(""), err
	}
	buf := make([]byte, 10240)

	serverMsg, err := conn.Read(buf)
	if err != nil {
		return []byte(""), err
	}

	return buf[:serverMsg], nil
}

func UdpConn(payload []byte, ip string, port int, timeout time.Duration) ([]byte, error) {
	portStr := strconv.Itoa(port)
	conn, err := net.DialTimeout("udp", ip+":"+portStr, timeout) // 绑定服务端地址
	if err != nil {
		return []byte(""), err
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) // 设置读写超时

	_, err = conn.Write([]byte(payload)) // 发送数据
	if err != nil {
		return []byte(""), err
	}
	buf := [1024]byte{}
	serverMsg, err := conn.Read(buf[:]) // 服务端返回的信息
	if err != nil {
		return []byte(""), err
	}
	return buf[:serverMsg], nil
}
