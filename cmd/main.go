package main

import (
	"fmt"
	"time"

	"github.com/talentsec/levscanner/core"
)

func main() {
	ip_list := []string{"139.155.83.171"}
	for _, ip := range ip_list {
		ab := core.Scan(ip, 80, "tcp", time.Second*5)
		fmt.Printf("Protocol: %v\n", ab)
	}
}
