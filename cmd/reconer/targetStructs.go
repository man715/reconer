package main

type Target struct {
	IP         string
	FoundPorts []FoundPort
}

type FoundPort struct {
	ServiceName string
	ScanPort    string
	Protocol    string
	Version     string
	HasSSL      bool
	Service     Service
}
