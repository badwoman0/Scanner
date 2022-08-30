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

//	通过接口查询IP具体属性,应确保每个ip只查找接口一次
func GetIPinfo(ip string) IPinfo {
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
