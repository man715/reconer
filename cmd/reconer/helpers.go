package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"runtime"
	"time"
)

// Sets the directory structure for each IP address
func setDirStruct(target *Target) {
	dirs := []string{"loot", "exploit", "www", "nmap"}
	for _, dir := range dirs {
		err = os.MkdirAll(target.IP+"/"+dir, 0755)
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

func replaceCmdOptions(target *Target) {
	patterns := [5]string{
		"{port}",
		"{address}",
		"{protocol}",
		"{scandir}",
		"{nmap_extra}",
	}

	for i, service := range target.Services {
		for j := range target.Services[i].Scans {
			for k, command := range target.Services[i].Scans[j].Commands {
				for _, pattern := range patterns {
					p := regexp.MustCompile(regexp.QuoteMeta(pattern))
					switch {
					case pattern == "{port}":
						cmd := p.ReplaceAllString(command, service.ScanPort)
						target.Services[i].Scans[j].Commands[k] = cmd
					}
				}
			}
		}
	}
}
