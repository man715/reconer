package main

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
	MYSQL       Service
	NFS         Service
	NTP         Service
	Oracle      Service
	POP3        Service
	RDP         Service
	RMI         Service
	RPC         Service
	SIP         Service
	SSH         Service
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
	Manuals      []ManualCommand `mapstructure:"manual"`
}

type Scan struct {
	Name     string
	Command  string
	Patterns []Pattern `mapstructure:"pattern"`
	RunOnce  string    `mapstructure:"run_once"`
}

type Pattern struct {
	Description string
	Pattern     string
}

type ManualCommand struct {
	Description string
	Commands    []string
}
