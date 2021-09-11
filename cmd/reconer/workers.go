package main

import (
	"log"
	"os"
	"sync"
)

// Worker for each IP address to have recon done on
func targetWorker(jobs <-chan *Target, enumConcurrency int, wg *sync.WaitGroup) {
	defer wg.Done()

	for target := range jobs {
		setDirStruct(target)

		var writerWg sync.WaitGroup
		writerWg.Add(2)
		outStream := make(chan map[string]interface{}, 20)
		errStream := make(chan map[string]interface{}, 20)
		go writeFile("results", outStream, target, &writerWg)
		go writeFile("err", errStream, target, &writerWg)

		// TCP All PLUS OS DETECTION SCAN
		log.Println("Starting nmap scan all ports and OS detection on", target.IP)
		filename := "fullTCP.nmap"
		cmd := "nmap -A --osscan-guess --version-all -p- -oN " + target.IP + "/nmap/" + filename + " " + target.IP
		runNmap(target, cmd, filename)

		if os.Getuid() == 0 {
			// UDP TOP 20 WITH SERVICE DETECTION
			log.Println("Starting nmap scan top 20 UDP ports on", target.IP)
			filename = "top20UDP.nmap"
			cmd = "nmap -sU -A --top-ports=20 --version-all -oN " + target.IP + "/nmap/" + filename + " " + target.IP
			runNmap(target, cmd, filename)
		}
		enumWorker(target, enumConcurrency, outStream, errStream)
		close(outStream)
		close(errStream)
		writerWg.Wait()
	}

}

// Worker for port enumeration
func enumWorker(target *Target, enumConcurrency int, outStream chan map[string]interface{}, errStream chan map[string]interface{}) {
	insertServiceInfo(target)
	replaceCmdOptions(target)
	var writerWg sync.WaitGroup
	writerWg.Add(1)
	var manualStream = make(chan map[string]interface{})
	go writeFile("", manualStream, target, &writerWg)

	filename := "manual"

	// Set up waitgroup
	var enumWg sync.WaitGroup
	// Set up channel
	enumJobs := make(chan map[string]string, 20)

	for i := 0; i < enumConcurrency; i++ {
		enumWg.Add(1)
		go runCommand(enumJobs, outStream, errStream, target, &enumWg)
	}

	for _, foundPort := range target.FoundPorts {
		for _, scan := range foundPort.Service.Scans {
			command := scan.Command
			cmd := make(map[string]string)
			cmd[scan.Name] = string(command)
			enumJobs <- cmd
		}

		counter := 0
		for _, manualCommands := range foundPort.Service.Manuals {
			for _, manualCommand := range manualCommands.Commands {
				writeCommand := make(map[string]interface{})
				writeCommand[filename] = manualCommand
				manualStream <- writeCommand
				counter++
			}
		}
	}

	close(enumJobs)
	enumWg.Wait()
	close(manualStream)
	writerWg.Wait()
}
