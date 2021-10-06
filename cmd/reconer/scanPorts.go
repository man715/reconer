package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

func runNmap(target *Target, cmd string, filename string, scanDir string) {
	command := strings.Split(cmd, " ")

	// Set up the STDOut and STDErr buffers
	var out bytes.Buffer
	var stderr bytes.Buffer

	nmap := exec.Command(command[0], command[1:]...)

	nmap.Stdout = &out
	nmap.Stderr = &stderr

	err := nmap.Start()
	if err != nil {
		log.Fatal("Could not run nmap: ", err)
	}

	// Wait for the process to finish or kill it after timeout
	done := make(chan error, 1)
	go func() {
		done <- nmap.Wait()
	}()

	// Set default timeout to 600 seconds (10 min)
	if timeout < 600 {
		timeout = 600
	}

	// Wait for either the done channel or the timeout to expire
	select {
	case <-time.After(timeout * time.Second):
		err = nmap.Process.Kill()
		if err != nil {
			log.Fatal("Failed to kill nmap: ", err)
		} else {
			log.Println("nmap killed as timeout reached on ", target.IP)
		}
	case err = <-done:
		if err != nil {
			log.Printf("nmap completed with an error on %v\n%v\n", target.IP, stderr.String())
		} else {
			log.Println("nmap finished successfully on ", target.IP)
		}
	}

	simpleWriteFile(scanDir, fmt.Sprint(nmap.Stdout), filename)
	simpleWriteFile(scanDir, fmt.Sprint(nmap.Stderr), "err_"+filename)

	// Load the nmap file
	file, err := os.Open(scanDir + filename)
	if err != nil {
		log.Println(err)
		log.Fatal("Failed to open the file: " + scanDir + filename)
	}
	defer file.Close()

	// Set the pattern to find ports and services
	var pattern string = `^(?P<port>\d+)\/(?P<protocol>(tcp|udp))(.*)open(\s*)(?P<service>[\w\-\/]+)(\s*)(?P<version>.*)$`
	scanner := bufio.NewScanner(file)
	serviceCounter := 0
	tmpSlice := make([]FoundPort, 0, 100)
	var tmpService FoundPort

	for scanner.Scan() {
		line := scanner.Text()
		// Scan the file for open ports
		r := regexp.MustCompile(pattern)
		match := r.FindStringSubmatch(line)
		result := make(map[string]string)
		if match != nil {
			// Set the result to a map where the capture group and result is stored
			for i, name := range r.SubexpNames() {
				if i != 0 && name != "" {
					result[name] = match[i]
				}
			}

			// Create a temp service to put into the tmp Slice
			tmpSlice = append(tmpSlice, tmpService)

			// If service uses SSL set HasSSL to true
			r = regexp.MustCompile(`ssl`)
			hasSSL := r.FindStringSubmatch(result["service"])

			// Populate the Service with the port and service information
			if hasSSL != nil {
				tmpSlice[serviceCounter].HasSSL = true
			}
			tmpSlice[serviceCounter].ServiceName = result["service"]
			tmpSlice[serviceCounter].ScanPort = result["port"]
			tmpSlice[serviceCounter].Protocol = result["protocol"]
			tmpSlice[serviceCounter].Version = result["version"]
			target.FoundPorts = tmpSlice
			serviceCounter++
		}

	}

}
