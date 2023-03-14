package main

import (
	"fmt"
	"time"

	"github.com/qingwei-wym/Scanner/core"
)

func main() {
	ip_list := []string{"39.105.46.33",
		"61.142.177.126"}
	portlist := []int{5222}
	for _, ip := range ip_list {
		for _, port := range portlist {
			fmt.Printf("start scan %v:%v\n", ip, port)
			ab := core.Scan(ip, port, "tcp", time.Second*5)
			fmt.Printf("Protocol: %v\n", ab.Protocol)
		}

	}
}
