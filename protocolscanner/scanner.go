package protocolscanner

import (
	"time"
)

type ProtocolResult struct {
	Ip        string
	Port      int
	Transport string
	Protocol  string
	Body      []byte
	Cert      string
	IsSsL     bool
}

func Tcpscanner(ip string, port int, tryProtocols []string, timeout time.Duration) ProtocolResult {
	var result = ProtocolResult{}
	var body []byte
	var cert string
	var ssl bool
	for _, tryProtocol := range tryProtocols {
		for _, protocolrule := range ProtocolRules_ {
			if protocolrule.Protocol == tryProtocol {
				for _, rule := range protocolrule.Rules {
					//发送此种协议探测包
					var payloadByte = []byte(rule.Payload)

					if protocolrule.IsSsl {
						body, cert, _ = TcpConnSSL(payloadByte, ip, port, timeout)
						ssl = true
					} else {
						body, _ = TcpConn(payloadByte, ip, port, timeout)
						cert = ""
						ssl = false
					}
					//利用协议规则文件判断协议返回包具有什么特征
					for _, match := range rule.Match {
						if matchPattern(match.Pattern, []byte(match.Keyword), body) {
							result = ProtocolResult{
								Ip:        ip,
								Port:      port,
								Transport: "tcp",
								Protocol:  protocolrule.Protocol,
								Body:      body,
								Cert:      cert,
								IsSsL:     ssl}
							return result
						}
					}

				}
			}
		}

	}
	if len(body) > 0 {
		result = ProtocolResult{
			Ip:        ip,
			Port:      port,
			Transport: "",
			Protocol:  "",
			Body:      body,
			Cert:      cert,
			IsSsL:     ssl}

		return result

	}
	result = ProtocolResult{
		Ip:        ip,
		Port:      port,
		Transport: "",
		Protocol:  "",
		Body:      []byte(""),
		Cert:      cert,
		IsSsL:     ssl}

	return result

}

func Udpscanner(ip string, port int, tryProtocols []string, timeout time.Duration) ProtocolResult {
	var result = ProtocolResult{}
	var body []byte
	for _, tryProtocol := range tryProtocols {
		for _, protocolrule := range ProtocolRules_ {
			if protocolrule.Protocol == tryProtocol {
				for _, rule := range protocolrule.Rules {
					//发送此种协议探测包
					var payloadByte = []byte(rule.Payload)
					body, _ = UdpConn(payloadByte, ip, port, timeout)
					//利用协议规则文件判断协议返回包具有什么特征
					for _, match := range rule.Match {
						if matchPattern(match.Pattern, []byte(match.Keyword), body) {
							result = ProtocolResult{
								Ip:        ip,
								Port:      port,
								Transport: "udp",
								Protocol:  protocolrule.Protocol,
								Body:      body}
							return result
						}
					}

				}
			}
		}

	}
	if len(body) > 0 {
		result = ProtocolResult{
			Ip:        ip,
			Port:      port,
			Transport: "",
			Protocol:  "",
			Body:      body}

		return result

	}
	result = ProtocolResult{
		Ip:        ip,
		Port:      port,
		Transport: "",
		Protocol:  "",
		Body:      []byte("")}

	return result

}
