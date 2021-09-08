package main

import (
	"log"
	"sync"

	"github.com/Ullaakut/nmap/v2"
)

// Run nmap TCP All Ports
func runNmapTcp(ip string, ports string, fileName string, wg *sync.WaitGroup) ([]nmap.Port, string, error) {
	// Set all ports as the default scan range
	if ports == "" {
		ports = "-65535"
	}

	// Set up the nmap scanner
	nmapScanner, err := nmap.NewScanner(
		nmap.WithTargets(ip),
		nmap.WithPorts(ports),
		nmap.WithServiceInfo(),
		nmap.WithDefaultScript(),
		nmap.WithNmapOutput(fileName),
		nmap.WithSkipHostDiscovery(),
		nmap.WithConnectScan(),
	)
	if err != nil {
		return nil, "", err
	}

	// Get the results of the scan
	result, warnings, err := nmapScanner.Run()
	if err != nil {
		return nil, "", err
	}

	if verbose == 1 {
		if warnings != nil {
			log.Println(warnings)
		}
	}

	var openPorts []nmap.Port
	var hostAddress nmap.Address

	for _, host := range result.Hosts {
		openPorts = host.Ports
		hostAddress = host.Addresses[0]
	}

	return openPorts, hostAddress.String(), nil
}

// nmap UDP top 20
func runNmapUdp(ip string, wg *sync.WaitGroup) {
	defer wg.Done()
	fileName := cwd + "/" + ip + "/nmap/udpTop20-defaultScripts.nmap"

	// Set up the nmap scanner
	nmapScanner, err := nmap.NewScanner(
		nmap.WithTargets(ip),
		nmap.WithUDPScan(),
		nmap.WithServiceInfo(),
		nmap.WithDefaultScript(),
		nmap.WithNmapOutput(fileName),
		nmap.WithSkipHostDiscovery(),
		nmap.WithConnectScan(),
		nmap.WithMostCommonPorts(20),
	)
	if err != nil {
		log.Fatal("Nmap UDP scan error: ", err)
	}

	// Get the results of the scan
	_, warnings, err := nmapScanner.Run()
	if err != nil {
		log.Fatal("Nmap UDP scan error ", err)
	}

	if verbose == 1 {
		if warnings != nil {
			log.Println(warnings)
		}
	}
}

// nmap vuln scripts TCP
func runNmapTcpVuln(ip string, wg *sync.WaitGroup) {
	defer wg.Done()
	ports := "-65535"
	fileName := cwd + "/" + ip + "/nmap/tcpAllPorts-vulnScripts.nmap"

	// Set up the nmap scanner
	nmapScanner, err := nmap.NewScanner(
		nmap.WithTargets(ip),
		nmap.WithPorts(ports),
		nmap.WithServiceInfo(),
		nmap.WithScripts("vuln"),
		nmap.WithNmapOutput(fileName),
		nmap.WithSkipHostDiscovery(),
		nmap.WithConnectScan(),
	)
	if err != nil {
		log.Fatal("Nmap Vuln Scripts scan error: ", err)
	}

	// Get the results of the scan
	_, warnings, err := nmapScanner.Run()
	if err != nil {
		log.Println("Nmap Vuln Scripts scan error: ", err)
	}

	if verbose == 1 {
		if warnings != nil {
			log.Println(warnings)
		}
	}
}
