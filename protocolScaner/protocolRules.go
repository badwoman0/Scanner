package protocolScaner

type ProtocolRule struct {
	Protocol string
	TcpPorts []int
	UdpPorts []int
	IsSsl    bool
	Rules    []Rule
}

type Rule struct {
	Payload []byte
	Match   []Matches
}

type Matches struct {
	Pattern string
	Keyword []byte
}

var ProtocolRules_ = []ProtocolRule{
	{
		Protocol: "ftp",
		TcpPorts: []int{21, 2121},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte(""),
			Match: []Matches{
				{
					Pattern: "prefix",
					Keyword: []byte("220"),
				},
				{
					Pattern: "prefix",
					Keyword: []byte("500"),
				},
				{
					Pattern: "prefix",
					Keyword: []byte("550"),
				},
				{
					Pattern: "prefix",
					Keyword: []byte("421"),
				},
			},
		},
		},
	},
	{
		Protocol: "rdp",
		TcpPorts: []int{3389},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte("\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"),
			Match: []Matches{
				{
					Pattern: "prefix",
					Keyword: []byte("\x03\x00\x00\x13\x0e"),
				},
				{
					Pattern: "prefix",
					Keyword: []byte("\x03\x00\x00\x0b\x06"),
				},
			},
		},
		},
	},
	{
		Protocol: "http",
		TcpPorts: []int{80, 8080},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte("GET / HTTP/1.0\r\n\r\n"),
			Match: []Matches{
				{
					Pattern: "prefix",
					Keyword: []byte("HTTP"),
				},
			},
		},
		},
	},
	{
		Protocol: "https",
		TcpPorts: []int{80, 443, 8080},
		UdpPorts: []int{},
		IsSsl:    true,
		Rules: []Rule{{
			Payload: []byte("GET / HTTP/1.0\r\n\r\n"),
			Match: []Matches{
				{
					Pattern: "prefix",
					Keyword: []byte("HTTP"),
				},
			},
		},
		},
	},
	{
		Protocol: "msrpc",
		TcpPorts: []int{135, 49152, 49154, 49153, 49155},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte("\x05\x00\x01\x03\x10\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00"),
			Match: []Matches{
				{
					Pattern: "equal",
					Keyword: []byte("\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x01\x00\x00\x00\x04\x00\x01\x05\x00\x00\x00\x00"),
				},
			},
		},
		},
	},
	{
		Protocol: "mysql",
		TcpPorts: []int{3306, 3307, 3310},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte(""),
			Match: []Matches{
				{
					Pattern: "contains",
					Keyword: []byte("mysql"),
				},
				{
					Pattern: "contains",
					Keyword: []byte("Mysql"),
				},
				{
					Pattern: "contains",
					Keyword: []byte("MySQL"),
				},
				{
					Pattern: "contains",
					Keyword: []byte("MariaDB"),
				},
			},
		},
		},
	},
	{
		Protocol: "ntp",
		TcpPorts: []int{},
		UdpPorts: []int{123, 1604, 4040},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte("\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x4f\x23\x4b\x71\xb1\x52\xf3"),
			Match: []Matches{
				{
					Pattern: "regex",
					Keyword: []byte("\x24[\x01-\x0f].............................................."),
				},
				{
					Pattern: "regex",
					Keyword: []byte("\xe4[\x00\x04].............................................."),
				},
				{
					Pattern: "regex",
					Keyword: []byte("\x1c[\x01-\x0f].............................................."),
				},
				{
					Pattern: "regex",
					Keyword: []byte("\xdc[\x00-\x0f].............................................."),
				},
				{
					Pattern: "regex",
					Keyword: []byte("\x5c\x03.............................................."),
				},
				{
					Pattern: "regex",
					Keyword: []byte("\x64\x03.............................................."),
				},
			},
		},
			{
				Payload: []byte("\x1e\x00\x01\x30\x02\xfd\xa8\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
				Match: []Matches{
					{
						Pattern: "regex",
						Keyword: []byte("\x1e\xc0\x010\x02\x00\xa8\xe3\x00\x00\x00\x00"),
					},
				},
			},
		},
	},
	{
		Protocol: "pptp",
		TcpPorts: []int{1723},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte("\x00\x9c\x00\x01\x1a\x2b\x3c\x4d\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\xff\xff\x00\x01\x6e\x6f\x6e\x65\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6e\x6d\x61\x70\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
			Match: []Matches{
				{
					Pattern: "prefix",
					Keyword: []byte("\x00\x9c\x00\x01\x1a\x2b\x3c\x4d\x00\x02\x00\x00\x01\x00\x01\x00"),
				},
			},
		},
		},
	},
	{
		Protocol: "rtsp",
		TcpPorts: []int{554, 8554},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte("GET / HTTP/1.0\r\n\r\n"),
			Match: []Matches{
				{
					Pattern: "prefix",
					Keyword: []byte("RTSP"),
				},
			},
		},
		},
	},
	{
		Protocol: "sip",
		TcpPorts: []int{5060},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte("\x4f\x50\x54\x49\x4f\x4e\x53\x20\x73\x69\x70\x3a\x6e\x6d\x20\x53\x49\x50\x2f\x32\x2e\x30\x0d\x0a\x56\x69\x61\x3a\x20\x53\x49\x50\x2f\x32\x2e\x30\x2f\x54\x43\x50\x20\x6e\x6d\x3b\x62\x72\x61\x6e\x63\x68\x3d\x66\x6f\x6f\x3b\x72\x70\x6f\x72\x74\x0d\x0a\x46\x72\x6f\x6d\x3a\x20\x3c\x73\x69\x70\x3a\x6e\x6d\x40\x6e\x6d\x3e\x3b\x74\x61\x67\x3d\x72\x6f\x6f\x74\x0d\x0a\x54\x6f\x3a\x20\x3c\x73\x69\x70\x3a\x6e\x6d\x32\x40\x6e\x6d\x32\x3e\x0d\x0a\x43\x61\x6c\x6c\x2d\x49\x44\x3a\x20\x35\x30\x30\x30\x30\x0d\x0a\x43\x53\x65\x71\x3a\x20\x34\x32\x20\x4f\x50\x54\x49\x4f\x4e\x53\x0d\x0a\x4d\x61\x78\x2d\x46\x6f\x72\x77\x61\x72\x64\x73\x3a\x20\x37\x30\x0d\x0a\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x4c\x65\x6e\x67\x74\x68\x3a\x20\x30\x0d\x0a\x43\x6f\x6e\x74\x61\x63\x74\x3a\x20\x3c\x73\x69\x70\x3a\x6e\x6d\x40\x6e\x6d\x3e\x0d\x0a\x41\x63\x63\x65\x70\x74\x3a\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x73\x64\x70\x0d\x0a\x0d\x0a"),
			Match: []Matches{
				{
					Pattern: "prefix",
					Keyword: []byte("SIP"),
				},
			},
		},
		},
	},
	{
		Protocol: "smtp",
		TcpPorts: []int{25, 587},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte(""),
			Match: []Matches{
				{
					Pattern: "contains",
					Keyword: []byte("ESMTP"),
				},
			},
		},
		},
	},
	{
		Protocol: "ssh",
		TcpPorts: []int{22, 2222, 22222},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte(""),
			Match: []Matches{
				{
					Pattern: "prefix",
					Keyword: []byte("SSH"),
				},
			},
		},
		},
	},
	{
		Protocol: "telnet",
		TcpPorts: []int{23, 2601, 2323},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte(""),
			Match: []Matches{
				{
					Pattern: "prefix",
					Keyword: []byte("\xff\xfd"),
				},
				{
					Pattern: "prefix",
					Keyword: []byte("\xff\xfb"),
				},
			},
		},
		},
	},
	{
		Protocol: "imap",
		TcpPorts: []int{143, 993},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte(""),
			Match: []Matches{
				{
					Pattern: "prefix",
					Keyword: []byte("* OK"),
				},
				{
					Pattern: "prefix",
					Keyword: []byte("* BYE"),
				},
			},
		},
		},
	},
	{
		Protocol: "pop3",
		TcpPorts: []int{110, 995},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte("\x55\x53\x45\x52\x20\x77\x6f\x72\x6c\x64\x40\x67\x6d\x61\x69\x6c\x2e\x63\x6f\x6d"),
			Match: []Matches{
				{
					Pattern: "prefix",
					Keyword: []byte("+OK"),
				},
			},
		},
		},
	},
	{
		Protocol: "vnc",
		TcpPorts: []int{5900},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte("GET / HTTP/1.0\r\n\r\n"),
			Match: []Matches{
				{
					Pattern: "prefix",
					Keyword: []byte("RFB "),
				},
			},
		},
		},
	},
	{
		Protocol: "upnp",
		TcpPorts: []int{},
		UdpPorts: []int{1900},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte("\x4d\x2d\x53\x45\x41\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x32\x33\x39\x2e\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x30\x3a\x31\x39\x30\x30\x0d\x0a\x53\x54\x3a\x20\x75\x70\x6e\x70\x3a\x72\x6f\x6f\x74\x64\x65\x76\x69\x63\x65\x0d\x0a\x4d\x61\x6e\x3a\x20\x22\x73\x73\x64\x70\x3a\x64\x69\x73\x63\x6f\x76\x65\x72\x22\x0d\x0a\x4d\x58\x3a\x20\x33\x0d\x0a\x0d\x0a"),
			Match: []Matches{
				{
					Pattern: "prefix",
					Keyword: []byte("HTTP"),
				},
			},
		},
		},
	},
	{
		Protocol: "postgres",
		TcpPorts: []int{5432},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte("\x00\x00\x00\x2a\x00\x03\x00\x00\x64\x61\x74\x61\x62\x61\x73\x65\x00\x74\x65\x6d\x70\x6c\x61\x74\x65\x30\x00\x75\x73\x65\x72\x00\x70\x6f\x73\x74\x67\x72\x65\x73\x00\x00"),
			Match: []Matches{
				{
					Pattern: "prefix",
					Keyword: []byte("\x00\x00\x00"),
				},
			},
		},
		},
	},
	{
		Protocol: "afp",
		TcpPorts: []int{548},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte("\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x0f\x00"),
			Match: []Matches{
				{
					Pattern: "contains",
					Keyword: []byte("AFP"),
				},
			},
		},
		},
	},
	{
		Protocol: "x11",
		TcpPorts: []int{6000, 6001},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte("\x6C\x00\x0B\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
			Match: []Matches{
				{
					Pattern: "prefix",
					Keyword: []byte("\x01\x00\x0b\x00\x00"),
				},
				{
					Pattern: "prefix",
					Keyword: []byte("\x00\x16\x0b\x00\x00\x00\x06\x00No protocol specified"),
				},
				{
					Pattern: "equal",
					Keyword: []byte("\x00\x2D\x0B\x00\x00\x00\x0C\x00"),
				},
				{
					Pattern: "equal",
					Keyword: []byte("\x00\x00\x00\x01\x00\x00\x00\x0c\x00\x00\x00\x00"),
				},
				{
					Pattern: "prefix",
					Keyword: []byte("\x00J\x0b\x00\x00"),
				},
			},
		},
		},
	},
	{
		Protocol: "mssql",
		TcpPorts: []int{1433, 1434},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte("\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x02\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x00\x00\x31\x32"),
			Match: []Matches{
				{
					Pattern: "prefix",
					Keyword: []byte("\x04\x01\x00"),
				},
			},
		},
		},
	},
	{
		Protocol: "mqtt",
		TcpPorts: []int{1883},
		UdpPorts: []int{},
		IsSsl:    false,
		Rules: []Rule{{
			Payload: []byte("\x10\x1f\x00\x04\x4d\x51\x54\x54\x04\xc2\x00\x0a\x00\x05\x41\xf0\xaa\x9b\x94\x00\x05\x41\xf0\xaa\x9b\x94\x00\x05\x41\xf0\xaa\x9b\x94"),
			Match: []Matches{
				{
					Pattern: "equal",
					Keyword: []byte("\x20\x02\x00\x00"),
				},
			},
		},
		},
	},
}
