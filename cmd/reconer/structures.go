package main

type Target struct {
	IP       string
	Services []TargetService
}

type TargetService struct {
	ServiceName string
	ScanPort    string
	Protocol    string
	HasSSL      bool
	Scans       []Scan
}
