package main

import (
	"log"
	"os"
	"sync"
)

// Worker for each IP address to have recon done on
func targetWorker(jobs <-chan *Target, enumConcurrency int, wg *sync.WaitGroup) {
	defer wg.Done()

	// Set up wait group for enumWorker
	var enumWg sync.WaitGroup
	//	var enumJobsList []*Target

	for target := range jobs {
		setDirStruct(target)
		// TCP All PLUS OS DETECTION SCAN
		log.Println("Starting nmap scan all ports and OS detection on", target.IP)
		filename := "fullTCP.nmap"
		cmd := "nmap -A --osscan-guess --version-all -p- -oN " + target.IP + "/nmap/" + filename + " " + target.IP
		runNmap(target, cmd, filename)

		if os.Getuid() == 0 {
			// UDP TOP 20 WITH SERVICE DETECTION
			log.Println("Starting nmap scan top 20 UDP ports on", target.IP)
			filename = "top20UDP.nmap"
			cmd = "nmap {nmap_extra} -sU -A --top-ports=20 --version-all -oN " + target.IP + "/nmap/" + filename + " " + target.IP
			runNmap(target, cmd, filename)
		}
		// Set up the jobs channel for service enumeration
		enumJobs := make(chan *Target)
		for i := 0; i < enumConcurrency; i++ {
			enumWg.Add(1)
			enumWorker(enumJobs, &enumWg)
		}
	}

}

// Worker for port enumeration
func enumWorker(enumJobs <-chan *Target, wg *sync.WaitGroup) {

	defer wg.Done()

}
