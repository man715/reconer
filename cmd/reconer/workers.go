package main

import (
	"log"
	"strconv"
	"strings"
	"sync"
)

// Worker for each IP address to have recon done on
func reconWorker(enumConcurrency int, jobs <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Set up wait group for reconWorker
	var reconWg sync.WaitGroup
	var enumJobsList []string

	for j := range jobs {
		setDirStruct(j)

		// nmap scan all TCP ports with default scripts
		log.Println("Starting nmap default scripts on", j)
		nmapOut := cwd + "/" + j + "/nmap/tcpAllPorts-defaultScripts.nmap"
		openPorts, hostAddress, err := runNmapTcp(j, "", nmapOut, &reconWg)
		if err != nil {
			log.Println(err)
		}
		if openPorts == nil || hostAddress == "" {
			log.Println("This host is not up ", j)
		}

		// Set up the Jobs channel for port enumeration
		enumJobs := make(chan []string, 10)

		// Create the port enumeration workers
		for i := 0; i < enumConcurrency; i++ {
			reconWg.Add(1)
			go enumWorker(enumJobs, hostAddress, &reconWg)
		}

		for _, port := range openPorts {

			// Iterate through each port to create the enumJobList
			portNumber := strconv.Itoa(int(port.ID))
			portState := port.State.String()

			// Populate the enumJobsList
			if portNumber == "80" && portState == "open" {
				enumJobsList = append(enumJobsList, "ffuf,"+portNumber)
				enumJobsList = append(enumJobsList, "nikto,"+portNumber)
				enumJobsList = append(enumJobsList, "whatweb,"+portNumber)
			} else if portNumber == "443" && portState == "open" {
				enumJobsList = append(enumJobsList, "ffuf,"+portNumber)
				enumJobsList = append(enumJobsList, "nikto,"+portNumber)
				enumJobsList = append(enumJobsList, "whatweb,"+portNumber)
			} else if portNumber == "445" && portState == "open" {
				enumJobsList = append(enumJobsList, "enum4linux, "+portNumber)
				enumJobsList = append(enumJobsList, "smbmap,"+portNumber)
				enumJobsList = append(enumJobsList, "smbclient,"+portNumber)
			}
		}

		// Add the port enumeration jobs to the enumJobs que
		for _, j := range enumJobsList {
			job := strings.Split(j, ",")
			enumJobs <- job
		}
		// Close the enumJobs channel after all jobs are loaded
		close(enumJobs)

		if runVuln == true {
			log.Println("Starting nmap Vuln scripts.")
			// Run TCP vunl scripts
			reconWg.Add(1)
			runNmapTcpVuln(j, &reconWg)
		}

		if runUdp == true {
			log.Println("Starting nmap UPD top 20")
			// Run UDP top 20 nmap scan
			reconWg.Add(1)
			runNmapUdp(j, &reconWg)
		}

		// Wait for all jobs to be finished
		reconWg.Wait()
	}
}

// Worker for port enumeration
func enumWorker(enumJobs <-chan []string, ip string, wg *sync.WaitGroup) {

	defer wg.Done()

	fileName := "result.txt"

	for job := range enumJobs {
		portNumber := job[1]
		jobName := job[0]

		if jobName == "enum4linux" {
			//run enum4linux
			runE4l(ip, fileName)
		} else if jobName == "onesixtyone" {
			// run onesixtyone
			// TODO
		} else if jobName == "ffuf" {
			// run ffuf
			runFfuf(ip, portNumber, portNumber+"-root.csv")
		} else if jobName == "whatweb" {
			// run whatweb
			runWhatweb(ip, portNumber, fileName)
		} else if jobName == "smbmap" {
			// run smbmap
			runSmbmap(ip, fileName)
		} else if jobName == "smbclient" {
			// run smbclient
			runSmbclient(ip, fileName)
		} else if jobName == "nikto" {
			// run nikto
			runNikto(ip, portNumber, fileName)
		}
	}
}
