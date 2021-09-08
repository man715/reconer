package main

type Target struct {
	IP                 string
	TCPPortScanResults map[string]string
	UDPPortScanREsults map[string]string
	Services           []Services
}

type Services struct {
	Name         string
	Scans        []Scan `mapstructure:"scan"`
	ScanPort     int
	ServiceNames []interface{}
	Version      string
	Protocol     string
}

type Scan struct {
	Commands       []interface{}
	HasRun         bool
	ManualCommands []interface{} `mapstructure:"manual"`
	Name           string
	PortsTCP       interface{} `mapstructure:"ports.tcp"`
	PortsUDP       interface{} `mapstructure:"ports.udp"`
	ResultsFile    string
	RunOnce        bool `mapstructure:"run_once"`
}
