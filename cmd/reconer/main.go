package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
)

func main() {
	scanConfigViper := viper.New()
	scanConfigViper.SetConfigName("serviceScans")
	scanConfigViper.AddConfigPath(".")
	err := scanConfigViper.ReadInConfig()
	if err != nil {
		log.Fatal(err)
	}
	scanConfigViper.Unmarshal(&scanConfig)

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

	// Check that a list of IPs were supplied
	if *ipFileList == "" && *ipList == "" {
		panic("[!] A list of IPs is required!")
	}

	// Make the reconJobs channel with a buffer size large enough to store an entire subnet set up wait group
	reconJobs := make(chan *Target, 255)
	var targetWg sync.WaitGroup

	// Start the heartbeat
	go heartbeat()

	// Create the recon workers
	for i := 0; i < concurrency; i++ {
		targetWg.Add(1)
		go targetWorker(reconJobs, enumConcurrency, &targetWg)
	}

	// Create the list of IPs for the reconJobs list
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

	// Populate the reconJobs que
	for _, ip := range ips {
		target := Target{IP: ip}
		reconJobs <- &target
	}
	// Close the channel
	close(reconJobs)

	targetWg.Wait()
}
