package ipinfo

import (
	"log"
	"net"

	"github.com/ipinfo/go/v2/ipinfo"
)

type IPinfo struct {
	IP          string
	City        string
	Region      string
	Country     string
	Loc         string
	Org         string
	Postal      string
	Timezone    string
	CountryName string
}
type Presetinfo struct {
	City        string
	Region      string
	Country     string
	Loc         string
	Org         string
	Postal      string
	Timezone    string
	CountryName string
}

//	通过接口查询IP具体属性,应确保每个ip只查找接口一次。 ifuseWe为true，则表示在可以使用公网，则使用公网接口查询，ifuseweb为false，则表示使用预制的地理位置信息。
func GetIPinfo(ip string, ifuseWeb bool, presetinfo Presetinfo) IPinfo {
	if ifuseWeb {
		return ipInfo(ip)
	} else {
		var res IPinfo
		res.IP = ip
		res.City = presetinfo.City
		res.Region = presetinfo.Region
		res.Country = presetinfo.Country
		res.Loc = presetinfo.Loc
		res.Org = presetinfo.Org
		res.Postal = presetinfo.Postal
		res.Timezone = presetinfo.Timezone
		res.CountryName = presetinfo.CountryName

		return res
	}
}

func ipInfo(ip string) IPinfo {
	client := ipinfo.NewClient(nil, nil, "343a80b11cd322")
	info, err := client.GetIPInfo(net.ParseIP("ip"))
	if err != nil {
		log.Fatal(err)
	}
	var result IPinfo
	result.IP = ip
	result.City = info.City
	result.Region = info.Region
	result.Country = info.Country
	result.Loc = info.Location
	result.Org = info.Org
	result.Postal = info.Postal
	result.Timezone = info.Timezone
	result.CountryName = info.CountryName
	return result

}

//https://ipinfo.io/8.8.8.8/json?token=343a80b11cd322
