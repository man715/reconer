package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Ullaakut/nmap/v2"
)

func main() {
	// check if running as root
	//if os.Geteuid() != 0 {
	//    panic("You need to run this as root, sorry!")
	//}

	// Set up arguments
	var concurrency int
	var enumConcurrency int

	flag.IntVar(&concurrency, "c", 20, "set how many IPs will be processed concurrently")
	flag.IntVar(&enumConcurrency, "e", 5, "Set how many scans can happen concurrently for each IP")
	ipFileList := flag.String("I", "", "A list of IP addresses separated by a line break")
	ipList := flag.String("i", "", "A list of IP addresses given at the commandline separated by a comma")
	t := flag.Int("t", 600, "Set the timeout in seconds")
	hb := flag.Int("hb", 60, "Set the heartbeat interval")
	v := flag.Int("v", 0, "Set the verbosity of the output 0 or 1")
	flag.BoolVar(&runUdp, "run-udp-scan", false, "Run UDP top 20 scan -run-udp-scan=true")
	flag.BoolVar(&runVuln, "run-vuln-scan", false, "Run Vul scripts on TCP ports -run-udp-scan=true")
	//flag.BoolVar(&runUdp,"ru",false, "Run udp on top 20 ports is off by default")
	//flag.BoolVar(&runVuln,"vu", false, "Run vuln scan on all TCP ports if off by default")

	flag.Usage = func() {
		flagSet := flag.CommandLine
		fmt.Printf("Usage of reconer:\n")
		order := []string{"c", "e", "hb", "i", "I", "run-udp-scan", "run-vuln-scan", "t", "v"}
		for _, name := range order {
			flag := flagSet.Lookup(name)
			fmt.Printf("-%s: %s\n", flag.Name, flag.Usage)
		}
	}

	flag.Parse()

	// Get the current working directory
	cwd, err = os.Getwd()
	if err != nil {
		panic(err)
	}

	// Set the global variables
	verbose = *v
	heartbeatInterval = time.Duration(*hb)
	timeout = time.Duration(*t)
	fmt.Printf("Verbosity: %d\nHeartbeat: %d seconds\nTimeout: %d seconds\nConcurrency: %d\n", *v, *hb, *t, concurrency)

	// Check that a list of IPs were supplied
	if *ipFileList == "" && *ipList == "" {
		panic("[!] A list of IPs is required!")
	}

	// Make the jobs channel with a buffer size large enough to store an entire subnet
	jobs := make(chan string, 255)

	// Set up wait group
	var wg sync.WaitGroup

	// Start the heartbeat
	go heartbeat()

	// Create the recon workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go reconWorker(enumConcurrency, jobs, &wg)
	}

	// Create the list of IPs for the jobs list
	var ips []string
	// Create the list from the commandline argument or file
	if *ipList != "" {
		ips = strings.Split(*ipList, ",")
	} else {
		fileBytes, err := ioutil.ReadFile(*ipFileList)

		if err != nil {
			log.Fatal("Error opening the file of IPs: ", err)
		}
		ips = strings.Split(string(fileBytes), "\n")

		// Clean up the list to remove the last item which is a blank space
		ips = ips[:len(ips)-1]
	}

	// Populate the jobs que
	for _, j := range ips {
		jobs <- j
	}
	// Close the channel
	close(jobs)

	wg.Wait()
}

// Sets the directory structure for each IP address
func setDirStruct(ip string) {
	dirs := []string{"loot", "exploit", "www", "nmap"}
	for _, dir := range dirs {
		err = os.MkdirAll(ip+"/"+dir, 0755)
		if err != nil {
			log.Fatal("Could not create the directory: ", err)
		}
	}
}

// Heartbeat to check the status.
func heartbeat() {
	for {
		timer := time.After(time.Second * heartbeatInterval)
		<-timer
		fmt.Printf("There are %d goroutines running\n", runtime.NumGoroutine())
	}
}

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

// This function will run enum4linux
func runE4l(ip string, fileName string) {
	err = os.MkdirAll(ip+"/e4l", 0755)
	if err != nil {
		log.Fatal("Could not create directory for enum4linux: ", err)
	}

	outputFile := cwd + "/" + ip + "/e4l/" + fileName
	proCommand := "enum4linux " + ip
	proArgs := strings.Split(proCommand, " ")

	// Set up the Stdout and Stderr buffers
	var out bytes.Buffer
	var stderr bytes.Buffer

	// Set up the command object
	cmd := exec.Command(proArgs[0], proArgs[1:]...)

	// Assign Stdout and Stderr
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	// Run the command
	err = cmd.Start()
	if err != nil {
		log.Fatal("Could not start ffuf: ", err)
	}

	// Wait for the process to finishe or kill it after timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Set timeout to 300 sec or more
	if timeout < 300 {
		timeout = 300
	}

	// Wait for either the done channel to return or the timeout to expire
	select {
	case <-time.After(timeout * time.Second):
		err = cmd.Process.Kill()
		if err != nil {
			log.Fatal("Failed to kill enum4linux: ", err)
		} else {
			log.Println("enum4linux killed as timeout reached on", ip)
		}
	case err = <-done:
		if err != nil {
			log.Println("enum4linux completed with an error on " + ip + ": " + stderr.String())
		} else {
			log.Println("enum4linux finished successfully on", ip)
		}

		// Create the outfile and write the command output to it
		outFile, err := os.Create(outputFile)
		if err != nil {
			log.Fatal("Could not create the output file for smbclient: ", err)
		}

		defer outFile.Close()

		_, err = outFile.WriteString(out.String())
		if err != nil {
			log.Fatal("could not write to enum4linux outFile: ", err)
		}

	}

}

// This function will run ffuf
func runFfuf(ip string, portNumber string, fileName string) {
	// create teh directory to store teh results in

	err = os.MkdirAll(ip+"/ffuf", 0755)
	if err != nil {
		log.Fatal("Could not create the directory for ffuf: ", err)
	}

	var protocol string
	if portNumber == "80" {
		protocol = "http://"
	} else {
		protocol = "https://"
	}

	url := protocol + ip + ":" + portNumber + "/FUZZ"
	wordlist := "/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt"
	outputFile := "ffuf/" + fileName
	proCommand := "ffuf -u " + url + " -w " + wordlist + " -ic -of csv -o " + cwd + "/" + ip + "/" + outputFile
	proArgs := strings.Split(proCommand, " ")

	// Set up the Stdout and Stderr buffers
	var out bytes.Buffer
	var stderr bytes.Buffer

	// Set up the command object
	cmd := exec.Command(proArgs[0], proArgs[1:]...)

	// Assign Stdout and Stderr
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	// Run the command
	err = cmd.Start()
	if err != nil {
		log.Fatal("Could not start ffuf: ", err)
	}

	// Wait for the process to finishe or kill it after timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Set timeout to 300 sec or more
	if timeout < 300 {
		timeout = 300
	}

	// Wait for either the done channel to return or the timeout to expire
	select {
	case <-time.After(timeout * time.Second):
		err = cmd.Process.Kill()
		if err != nil {
			log.Fatal("Failed to kill ffuf: ", err)
		} else {
			log.Println("ffuf killed as timeout reached on", ip)
		}
	case err = <-done:
		if err != nil {
			log.Println("ffuf completed with an error on " + ip + ": " + stderr.String())
		} else {
			log.Println("ffuf finished successfully on", ip)
		}
	}

}

// whatweb
func runWhatweb(ip string, portNumber string, fileName string) {
	err = os.MkdirAll(ip+"/whatweb", 0755)
	if err != nil {
		log.Fatal("Could not create directory for whatweb: ", err)
	}
	outputFile := cwd + "/" + ip + "/whatweb/" + fileName

	var protocol string
	if portNumber == "80" {
		protocol = "http://"
	} else if portNumber == "443" {
		protocol = "https://"
	}
	url := protocol + ip + ":" + portNumber

	proCommand := "whatweb -a 3 " + url
	proArgs := strings.Split(proCommand, " ")

	// Set up the Stdout and Stderr buffers
	var out bytes.Buffer
	var stderr bytes.Buffer

	// Set up the command object
	cmd := exec.Command(proArgs[0], proArgs[1:]...)

	// Assign Stdout and Stderr
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	// Run the command
	err = cmd.Start()
	if err != nil {
		log.Fatal("Could not start ffuf: ", err)
	}

	// Wait for the process to finishe or kill it after timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Set timeout to 300 sec or more
	if timeout < 300 {
		timeout = 300
	}

	// Wait for either the done channel to return or the timeout to expire
	select {
	case <-time.After(timeout * time.Second):
		err = cmd.Process.Kill()
		if err != nil {
			log.Fatal("Failed to kill whatweb: ", err)
		} else {
			log.Println("whatweb killed as timeout reached on", ip)
		}
	case err = <-done:
		if err != nil {
			log.Println("whatweb completed with an error on " + ip + ": " + stderr.String())
		} else {
			log.Println("whatweb finished successfully on", ip)
		}

		// Create the outfile and write the command output to it
		outFile, err := os.Create(outputFile)
		if err != nil {
			log.Fatal("Could not create the output file for whatweb: ", err)
		}

		defer outFile.Close()

		_, err = outFile.WriteString(out.String())
		if err != nil {
			log.Fatal("could not write to whatweb outFile: ", err)
		}

	}

}

// smbmap
func runSmbmap(ip string, fileName string) {
	err = os.MkdirAll(ip+"/smbmap", 0755)
	if err != nil {
		log.Fatal("Could not create directory for smbmap: ", err)
	}

	outputFile := cwd + "/" + ip + "/smbmap/" + fileName
	proCommand := "smbmap -u \"\" -H " + ip
	proArgs := strings.Split(proCommand, " ")

	// Set up the Stdout and Stderr buffers
	var out bytes.Buffer
	var stderr bytes.Buffer

	// Set up the command object
	cmd := exec.Command(proArgs[0], proArgs[1:]...)

	// Assign Stdout and Stderr
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	// Run the command
	err = cmd.Start()
	if err != nil {
		log.Fatal("Could not start smbmap: ", err)
	}

	// Wait for the process to finishe or kill it after timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Set timeout to 300 sec or more
	if timeout < 300 {
		timeout = 300
	}

	// Wait for either the done channel to return or the timeout to expire
	select {
	case <-time.After(timeout * time.Second):
		err = cmd.Process.Kill()
		if err != nil {
			log.Fatal("Failed to kill smbmap: ", err)
		} else {
			log.Println("smbmap killed as timeout reached on", ip)
		}
	case err = <-done:
		if err != nil {
			log.Println("smbmap completed with an error on " + ip + ": " + stderr.String())
		} else {
			log.Println("smbmap finished successfully on", ip)
		}
		// Create the outfile and write the command output to it
		outFile, err := os.Create(outputFile)
		if err != nil {
			log.Fatal("Could not create the output file for smbmap: ", err)
		}

		defer outFile.Close()

		_, err = outFile.WriteString(out.String())
		if err != nil {
			log.Fatal("could not write to smbmap outFile: ", err)
		}

	}

}

// smbclient
func runSmbclient(ip string, fileName string) {
	err = os.MkdirAll(ip+"/smbclient", 0755)
	if err != nil {
		log.Fatal("Could not create directory for smbclient: ", err)
	}

	outputFile := cwd + "/" + ip + "/smbclient/" + fileName
	proCommand := "smbclient --no-pass -L " + ip
	proArgs := strings.Split(proCommand, " ")

	// Set up the Stdout and Stderr buffers
	var out bytes.Buffer
	var stderr bytes.Buffer

	// Set up the command object
	cmd := exec.Command(proArgs[0], proArgs[1:]...)

	// Assign Stdout and Stderr
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	// Run the command
	err = cmd.Start()
	if err != nil {
		log.Fatal("Could not start smbclient: ", err)
	}

	// Wait for the process to finishe or kill it after timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Set timeout to 300 sec or more
	if timeout < 300 {
		timeout = 300
	}

	// Wait for either the done channel to return or the timeout to expire
	select {
	case <-time.After(timeout * time.Second):
		err = cmd.Process.Kill()
		if err != nil {
			log.Fatal("Failed to kill smbclient: ", err)
		} else {
			log.Println("smbclient killed as timeout reached on", ip)
		}
	case err = <-done:
		if err != nil {
			log.Println("smbclient completed with an error on " + ip + ": " + stderr.String())
		} else {
			log.Println("smbclient finished successfully on", ip)
		}

		// Create the outfile and write the command output to it
		outFile, err := os.Create(outputFile)
		if err != nil {
			log.Fatal("Could not create the output file for smbclient: ", err)
		}

		defer outFile.Close()

		_, err = outFile.WriteString(out.String())
		if err != nil {
			log.Fatal("could not write to smbclient outFile: ", err)
		}
	}

}

// nikto
func runNikto(ip string, portNumber string, fileName string) {
	err = os.MkdirAll(ip+"/nikto", 0755)
	if err != nil {
		log.Fatal("Could not create directory for nikto: ", err)
	}

	outputFile := cwd + "/" + ip + "/nikto/" + fileName

	var protocol string
	if portNumber == "80" {
		protocol = "http://"
	} else if portNumber == "443" {
		protocol = "https://"
	}

	url := protocol + ip + ":" + portNumber
	proCommand := "nikto -host=" + url
	proArgs := strings.Split(proCommand, " ")

	// Set up the Stdout and Stderr buffers
	var out bytes.Buffer
	var stderr bytes.Buffer

	// Set up the command object
	cmd := exec.Command(proArgs[0], proArgs[1:]...)

	// Assign Stdout and Stderr
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	// Run the command
	err = cmd.Start()
	if err != nil {
		log.Fatal("Could not start ffuf: ", err)
	}

	// Wait for the process to finishe or kill it after timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Set timeout to 900 sec or more
	if timeout < 900 {
		timeout = 900
	}

	// Wait for either the done channel to return or the timeout to expire
	select {
	case <-time.After(timeout * time.Second):
		err = cmd.Process.Kill()
		if err != nil {
			log.Fatal("Failed to kill nikto ", err)
		} else {
			log.Println("nikto killed as timeout reached on", ip)
		}
	case err = <-done:
		if err != nil {
			log.Println("nikto completed with an error on " + ip + ": " + stderr.String())
		} else {
			log.Println("nikto finished successfully on", ip)
		}

		// Create the outfile and write the command output to it
		outFile, err := os.Create(outputFile)
		if err != nil {
			log.Fatal("Could not create the output file for nikto: ", err)
		}

		defer outFile.Close()

		_, err = outFile.WriteString(out.String())
		if err != nil {
			log.Fatal("could not write to nikto outFile: ", err)
		}
	}

}
