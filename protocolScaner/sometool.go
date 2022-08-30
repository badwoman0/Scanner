package protocolScaner

import (
	"bytes"
	"sort"
)

func matchPattern(pattern string, keyword []byte, body []byte) bool {

	switch pattern {
	case "prefix":
		if len(body) >= len(keyword) {
			return bytes.Equal(keyword, body[0:len(keyword)])
		}

	case "contains":

		return bytes.Contains(body, keyword)

	case "equal":
		if len(body) >= len(keyword) {
			return bytes.Equal(keyword, body[0:len(keyword)])
		}

	case "regex":
		// todo:需要编写正则匹配规则的逻辑
		break

	default:
		return false
	}

	return false
}

// 返回协议集合的端口号，应只在初始化时调用一次

func GetPortsRange() ([]int, []int, map[int][]string, map[int][]string) {

	var tcpPortRangeTemp = map[int][]string{}
	var udpPortRangeTemp = map[int][]string{}

	for _, protocolRule := range ProtocolRules_ {

		for i := range protocolRule.TcpPorts {
			portstr := protocolRule.TcpPorts[i]
			_, ok := tcpPortRangeTemp[i]

			if ok {
				tcpPortRangeTemp[portstr] = append(tcpPortRangeTemp[portstr], protocolRule.Protocol)

			} else {
				tcpPortRangeTemp[portstr] = []string{protocolRule.Protocol}
			}
		}

		for i := range protocolRule.UdpPorts {
			portstr := protocolRule.UdpPorts[i]
			_, ok := udpPortRangeTemp[portstr]

			if ok {
				udpPortRangeTemp[portstr] = append(udpPortRangeTemp[portstr], protocolRule.Protocol)

			} else {
				udpPortRangeTemp[portstr] = []string{protocolRule.Protocol}
			}
		}
	}
	var tcpPortRange = map[int][]string{}
	var udpPortRange = map[int][]string{}

	var tcpkeys []int
	for k := range tcpPortRangeTemp {
		tcpkeys = append(tcpkeys, k)
	}
	sort.Ints(tcpkeys)
	// 索引0的意思是对于不在端口范围内的端口采用top50协议的payload进行探测
	tcpPortRange[0] = []string{"http", "https", "rtsp", "mysql"}
	for _, k := range tcpkeys {
		tcpPortRange[k] = tcpPortRangeTemp[k]

	}

	var udpkeys []int
	for k := range udpPortRangeTemp {
		udpkeys = append(udpkeys, k)
	}
	sort.Ints(udpkeys)
	// 索引0的意思是对于不在端口范围内的端口采用top50协议的payload进行探测
	udpPortRange[0] = []string{"ntp"}

	for _, k := range udpkeys {
		udpPortRange[k] = udpPortRangeTemp[k]

	}
	return tcpkeys, udpkeys, tcpPortRange, udpPortRange

}
