package devicescanner

import "strings"

type Resp struct {
	RespBody     string
	RespBanner   string
	RespTitle    string
	RespCert     string
	RespHeader   string
	RespServer   string
	RespProtocol string
	RespPort     string
}

func (r *Resp) Body(s string) bool {
	return strings.Contains(r.RespBody, s)
}

func (r *Resp) Banner(s string) bool {
	return strings.Contains(r.RespBanner, s)
}

func (r *Resp) Cert(s string) bool {
	return strings.Contains(r.RespCert, s)
}

func (r *Resp) Header(s string) bool {
	return strings.Contains(r.RespHeader, s)
}
func (r *Resp) Title(s string) bool {
	return r.RespTitle == s
}
func (r *Resp) Server(s string) bool {

	return r.RespServer == s

}

func (r *Resp) Protocol(s string) bool {
	return r.RespProtocol == s
}

func (r *Resp) Port(s string) bool {
	return r.RespPort == s
}

type RuleFunc func(Resp) bool

type RuleInfo struct {
	CountryCode      uint32
	Company          string
	Product          string
	ProductUrl       string
	FirstCategoryId  string
	SecondCategoryId string
}

type Rule struct {
	Id    uint32
	Soft  bool
	Level uint8
	Info  RuleInfo
	Func  RuleFunc
}

var demo = Rule{
	Id:    10002,
	Soft:  false,
	Level: 4,
	Info: RuleInfo{
		CountryCode: 1,
		Company:     "二六三企业通信有限公司",
		Product:     "263企业邮箱",
	},
	Func: func(resp Resp) bool {
		return (((resp.Body("net263.wm.custom_login.homepage_init")) || (resp.Title("263企业邮箱"))) || (resp.Cert("Subject: c=CN, st=Beijing, l=Beijing, o=Beijing 263 Enterprise Correspondence CO.,Ltd"))) || (resp.Body("src=\"/custom_login/js/net263_wm_util.js"))
	},
}
