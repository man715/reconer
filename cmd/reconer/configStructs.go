package main

// func replaceCmdOptions(target *Target) {
// 	origCmdPtr := &target.Services[0].Scans[0].Commands[0]
// 	origCmd := target.Services[0].Scans[0].Commands[0]
// 	cmd := origCmd.(string)
// 	patterns := [5]string{
// 		"{port}",
// 		"{address}",
// 		"{protocol}",
// 		"{scandir}",
// 		"{nmap_extra}",
// 	}
//
// 	for _, pattern := range patterns {
// 		p := regexp.MustCompile(regexp.QuoteMeta(pattern))
//
// 		switch {
// 		case pattern == "{port}":
// 			cmd = p.ReplaceAllString(cmd, strconv.Itoa(target.Services[0].ScanPort))
// 		default:
// 			cmd = p.ReplaceAllString(cmd, "FUZZYOUFUZZER")
// 		}
// 	}
// 	*origCmdPtr = cmd
// 	fmt.Println(cmd)
// }

type ScanConfig struct {
	AllServices Service
	Cassandra   Service
	Cups        Service
	Distcc      Service
	DNS         Service
	Finger      Service
	FTP         Service
	HTTP        Service
	IMAP        Service
	Kerberos    Service
	LDAP        Service
	Mongodb     Service
	MSSQL       Service
	NFS         Service
	NTP         Service
	Oracle      Service
	POP3        Service
	RDP         Service
	RMI         Service
	RPC         Service
	SIP         Service
	SMB         Service
	SMTP        Service
	SNMP        Service
	Telnet      Service
	TFTP        Service
	VNC         Service
}

type Service struct {
	ServiceNames []interface{}
	Scans        []Scan          `mapstructure:"scan"`
	Manual       []ManualCommand `mapstructure:"scan"`
}

type Scan struct {
	Name     string
	Commands []string
	Patterns []Pattern `mapstructure:"pattern"`
}

type Pattern struct {
	Description string
	Pattern     string
}

type ManualCommand struct {
	Description string
	Commands    []string
}
