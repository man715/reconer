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
      portService := port.Service.Name

			// Populate the enumJobsList
      switch portService {
      case "http","https":
				enumJobsList = append(enumJobsList, "ffuf,"+portNumber+","+portService)
				enumJobsList = append(enumJobsList, "nikto,"+portNumber+","+portService)
				enumJobsList = append(enumJobsList, "whatweb,"+portNumber+","+portService)
      case "smb":
				enumJobsList = append(enumJobsList, "enum4linux, "+portNumber+","+portService)
				enumJobsList = append(enumJobsList, "smbmap,"+portNumber+","+portService)
				enumJobsList = append(enumJobsList, "smbclient,"+portNumber+","+portService)
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
		jobName := job[0]
		portNumber := job[1]
    portService := job[2]

    switch jobName {
    case "ffuf":
			// run ffuf
			runFfuf(ip, portService, portNumber, portNumber+"-root.csv")
    case "whatweb":
			// run whatweb
			runWhatweb(ip, portService, portNumber, fileName)
    case "nikto":
			// run nikto
			runNikto(ip, portService, portNumber, fileName)
    case "smbmap":
			// run smbmap
			runSmbmap(ip, fileName)
    case "smbclient":
			// run smbclient
			runSmbclient(ip, fileName)
    case "enum4linux":
      // run enum4linux
      runE4l(ip, fileName)
    case "onesixtyone":
      // TODO
    }
	}
}
