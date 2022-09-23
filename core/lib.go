package core

import (
	"fmt"
	"strconv"
	"time"

	"github.com/talentsec/levscanner/asmtomsf"
	"github.com/talentsec/levscanner/devicescanner"
	"github.com/talentsec/levscanner/protocolscanner"
)

type Asset struct {
	Id               uint32
	Product          string
	ProductUrl       string
	FirstCategoryId  string
	SecondCategoryId string
	Company          string
	SoftHardCode     bool
	LevelCode        uint8
}

type IpDetails struct {
	Ip     string
	Port   int
	IpPort string
	Os     string

	Protocol  string
	SSL       bool
	CrawlTime string
	Transport string
	HonneyPot bool
	IsWeb     bool

	Title       string
	Header      string
	StatusCode  string
	Server      string
	Banner      string
	Body        string
	Cert        string
	Assets      []Asset
	MsfExpPaths []string
}

func GetExps(res IpDetails) []string {
	protocol := res.Protocol
	var msfPathes = []string{}
	for _, i := range asmtomsf.SupportProtocols {
		for _, j := range i.Protocols {
			if protocol == j {
				msfPathes = i.MsfPaths
				return msfPathes
			}
		}
	}

	return asmtomsf.OtherMsfPathes
}

func ProtocolScan(ip string, port int, transport string, timeout time.Duration) protocolscanner.ProtocolResult {
	tcpkeys, udpkeys, tcpPortRange, udpPortRange := protocolscanner.GetPortsRange()

	var protocolresult protocolscanner.ProtocolResult
	switch transport {
	case "tcp":
		//判断要扫描的tcp端口是否在我们定义的协议端口中

		for _, v := range tcpkeys {
			if port == v {
				//在定义的端口里的逻辑
				protocolresult = protocolscanner.Tcpscanner(ip, port, tcpPortRange[port], timeout)
				if protocolresult.Protocol == "" {
					protocolresult = protocolscanner.Tcpscanner(ip, port, tcpPortRange[0], timeout)
				}
				return protocolresult
			}
		}
		protocolresult = protocolscanner.Tcpscanner(ip, port, tcpPortRange[0], timeout)
		return protocolresult
	case "udp":
		//判断要扫描的udp端口是否在我们定义的协议端口中
		for _, v := range udpkeys {
			if port == v {
				//在定义的端口里的逻辑
				protocolresult = protocolscanner.Udpscanner(ip, port, udpPortRange[port], timeout)
				if protocolresult.Protocol == "" {
					protocolresult = protocolscanner.Udpscanner(ip, port, udpPortRange[0], timeout)
				}
				return protocolresult
			}
		}
		protocolresult = protocolscanner.Udpscanner(ip, port, udpPortRange[0], timeout)
		return protocolresult

	}

	return protocolresult

}

func Scan(ip string, port int, transport string, timeout time.Duration) IpDetails {
	var result IpDetails
	var waitParse devicescanner.Resp
	var asset Asset
	result.Assets = []Asset{}
	a := ProtocolScan(ip, port, transport, timeout)
	result.Ip = a.Ip
	result.Port = a.Port
	result.Transport = a.Transport
	result.Protocol = a.Protocol
	result.Cert = a.Cert
	result.SSL = a.IsSsL
	if result.Protocol == "http" || result.Protocol == "https" {
		wpd := protocolscanner.WebProtocolPraser(string(a.Body))
		result.IsWeb = true
		result.Body = wpd.Body
		result.Banner = wpd.Banner
		result.Header = wpd.Header
		result.Server = wpd.Server
		result.StatusCode = wpd.StatusCode
		result.Title = wpd.Title

	} else {
		result.Body = fmt.Sprintf("%q", a.Body)
	}
	result.Banner = result.Body
	waitParse = devicescanner.Resp{
		RespBody:     result.Body,
		RespBanner:   result.Banner,
		RespTitle:    result.Title,
		RespCert:     result.Cert,
		RespHeader:   result.Header,
		RespServer:   result.Server,
		RespProtocol: result.Protocol,
		RespPort:     strconv.Itoa(result.Port),
	}
	for _, k := range devicescanner.Rules {

		if k.Func(waitParse) {
			asset = Asset{
				Id:               k.Id,
				Product:          k.Info.Product,
				ProductUrl:       k.Info.ProductUrl,
				FirstCategoryId:  devicescanner.Category[k.Info.FirstCategoryId],
				SecondCategoryId: devicescanner.Category[k.Info.SecondCategoryId],
				Company:          k.Info.Company,
				SoftHardCode:     k.Soft,
				LevelCode:        k.Level,
			}
			result.Assets = append(result.Assets, asset)
		}
	}
	result.MsfExpPaths = GetExps(result)
	return result
}
