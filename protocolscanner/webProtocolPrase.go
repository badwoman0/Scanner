package protocolscanner

import (
	"regexp"
	"strings"
)

type WebProtocolDetail struct {
	Body       string
	Title      string
	Header     string
	StatusCode string
	Server     string
	Banner     string
}

//此函数的作用是从原始的协议返回报文解析出http协议的某些字段
func WebProtocolPraser(body string) WebProtocolDetail {
	var wpd WebProtocolDetail

	if len(strings.SplitAfterN(body, "\r\n\r\n", 2)) == 2 {
		header, webbody := strings.SplitAfterN(body, "\r\n\r\n", 2)[0], strings.Split(body, "\r\n\r\n")[1]
		reTitle := regexp.MustCompile(`<title>(.*)</title>`)
		title := reTitle.FindString(webbody)
		title = strings.Replace(title, "<title>", "", 1)
		title = strings.Replace(title, "</title>", "", 1)

		reServer := regexp.MustCompile(`Server: (.*?)\n`)

		server := reServer.FindString(header)
		server = strings.Replace(server, "Server: ", "", 1)
		server = strings.Replace(server, "\r\n", "", 1)

		reStatusCode := regexp.MustCompile(`HTTP/....(...)`)
		statusCode := reStatusCode.FindString(header)
		if len(statusCode) == 12 {
			statusCode = statusCode[len(statusCode)-3:]
		} else {
			statusCode = ""
		}

		wpd.Body = body
		wpd.Banner = body
		wpd.Header = header
		wpd.Server = server
		wpd.StatusCode = statusCode
		wpd.Title = title

	} else {
		wpd.Body = body
		wpd.Banner = body
		wpd.Header = ""
		wpd.Server = ""
		wpd.StatusCode = ""
		wpd.Title = ""

	}
	return wpd
}
