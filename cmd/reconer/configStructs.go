package main

type ScanConfig struct {
	UsernameWordlist string
	PasswordWordlist string
	AllServices      Service
	Cassandra        Service
	Cups             Service
	Distcc           Service
	DNS              Service
	Finger           Service
	FTP              Service
	HTTP             Service
	IMAP             Service
	Kerberos         Service
	LDAP             Service
	Mongodb          Service
	MSSQL            Service
	MYSQL            Service
	NFS              Service
	NTP              Service
	Oracle           Service
	POP3             Service
	RDP              Service
	RMI              Service
	RPC              Service
	SIP              Service
	SSH              Service
	SMB              Service
	SMTP             Service
	SNMP             Service
	Telnet           Service
	TFTP             Service
	VNC              Service
}

type Service struct {
	ServiceNames []interface{}
	Scans        []Scan          `mapstructure:"scan"`
	Manuals      []ManualCommand `mapstructure:"manual"`
}

type Scan struct {
	Name    string
	Command string
	Pattern Pattern `mapstructure:"pattern"`
	RunOnce string  `mapstructure:"run_once"`
}

type Pattern struct {
	Description string
	Pattern     string
}

type ManualCommand struct {
	Description string
	Commands    []string
}

type PortScanConfig struct {
	Default PortScanType
	Quick   PortScanType
	UDP     PortScanType
}

type PortScanType struct {
	Scans []PortScan `mapstructure:"scan"`
}
type PortScan struct {
	Name    string
	Command string
	Pattern string
}
