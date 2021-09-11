package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
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

func replacePlaceHolders(command string, port string, ip string, protocol string, directory string, hasSSL bool) string {
	patterns := [6]string{
		"{port}",
		"{address}",
		"{protocol}",
		"{scandir}",
		"{scheme}",
		"{nmap_extra}",
	}

	for _, pattern := range patterns {
		p := regexp.MustCompile(regexp.QuoteMeta(pattern))
		switch {
		case pattern == "{port}":
			command = p.ReplaceAllString(command, port)
			fallthrough
		case pattern == "{address}":
			command = p.ReplaceAllString(command, ip)
			fallthrough
		case pattern == "{protocol}":
			command = p.ReplaceAllString(command, protocol)
			fallthrough
		case pattern == "{scandir}":
			command = p.ReplaceAllString(command, directory)
			fallthrough
		case pattern == "{scheme}":
			scheme := "http"
			if hasSSL {
				scheme = "https"
			}
			command = p.ReplaceAllString(command, scheme)
			fallthrough
		case pattern == "{nmap_extra}":
			command = p.ReplaceAllString(command, "")
		}
	}

	return command
}

func replaceCmdOptions(target *Target) {

	// Replace the scan commands
	for i, service := range target.FoundPorts {
		for _, scan := range target.FoundPorts[i].Service.Scans {
			replacePlaceHolders(scan.Command, service.ScanPort, target.IP, service.Protocol, cwd+"/"+target.IP+"/", service.HasSSL)
		}
	}

	// Replace the manual commands

	for i, service := range target.FoundPorts {
		for j := range target.FoundPorts[i].Service.Manuals {
			for _, command := range target.FoundPorts[i].Service.Manuals[j].Commands {
				replacePlaceHolders(command, service.ScanPort, target.IP, service.Protocol, cwd+"/"+target.IP+"/", service.HasSSL)
			}
		}
	}

}

func insertServiceInfo(target *Target) {

	// Get the service names from the struct.
	for index, service := range target.FoundPorts {
		// Remove anything before a / to include the / if it exists in the ServiceName
		match := regexp.MustCompile("^(.*?)/(.*)$")
		replace := "${2}"
		serviceName := match.ReplaceAllString(service.ServiceName, replace)

		switch serviceName {
		case "apani1":
			target.FoundPorts[index].Service.Scans = scanConfig.Cassandra.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.Cassandra.Manuals
		case "ipp":
			target.FoundPorts[index].Service.Scans = scanConfig.Cups.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.Cups.Manuals
		case "distccd":
			target.FoundPorts[index].Service.Scans = scanConfig.Distcc.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.Distcc.Manuals
		case "domain":
			target.FoundPorts[index].Service.Scans = scanConfig.Finger.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.Finger.Manuals
		case "ftp", "ftp-data":
			target.FoundPorts[index].Service.Scans = scanConfig.FTP.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.FTP.Manuals
		case "http":
			target.FoundPorts[index].Service.Scans = scanConfig.HTTP.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.HTTP.Manuals
		case "imap":
			target.FoundPorts[index].Service.Scans = scanConfig.IMAP.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.IMAP.Manuals
		case "kerberos", "kpasswd":
			target.FoundPorts[index].Service.Scans = scanConfig.Kerberos.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.Kerberos.Manuals
		case "ldap":
			target.FoundPorts[index].Service.Scans = scanConfig.LDAP.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.LDAP.Manuals
			fmt.Println("LDAP")
		case "mongod":
			target.FoundPorts[index].Service.Scans = scanConfig.Mongodb.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.Mongodb.Manuals
		case "mssql", "ms-sql":
			target.FoundPorts[index].Service.Scans = scanConfig.MSSQL.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.MSSQL.Manuals
		case "mysql":
			target.FoundPorts[index].Service.Scans = scanConfig.MYSQL.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.MYSQL.Manuals
		case "nfs", "rpcbind":
			target.FoundPorts[index].Service.Scans = scanConfig.NFS.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.NFS.Manuals
		case "nntp":
			target.FoundPorts[index].Service.Scans = scanConfig.NTP.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.NTP.Manuals
		case "oracle":
			target.FoundPorts[index].Service.Scans = scanConfig.Oracle.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.Oracle.Manuals
		case "pop3":
			target.FoundPorts[index].Service.Scans = scanConfig.POP3.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.POP3.Manuals
		case "rdp", "ms-wbt-server", "ms-term-serv":
			target.FoundPorts[index].Service.Scans = scanConfig.RDP.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.RDP.Manuals
		case "java-rmi", "rmiregistry":
			target.FoundPorts[index].Service.Scans = scanConfig.RMI.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.RMI.Manuals
		case "msrpc", "erpc":
			target.FoundPorts[index].Service.Scans = scanConfig.RPC.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.RPC.Manuals
		case "asterisk":
			target.FoundPorts[index].Service.Scans = scanConfig.SIP.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.SIP.Manuals
		case "ssh":
			target.FoundPorts[index].Service.Scans = scanConfig.SSH.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.SSH.Manuals
		case "smb", "microsoft-ds", "netbios":
			target.FoundPorts[index].Service.Scans = scanConfig.SMB.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.SMB.Manuals
		case "smtp":
			target.FoundPorts[index].Service.Scans = scanConfig.SMTP.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.SMTP.Manuals
		case "snmp":
			target.FoundPorts[index].Service.Scans = scanConfig.SNMP.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.SNMP.Manuals
		case "telent":
			target.FoundPorts[index].Service.Scans = scanConfig.Telnet.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.Telnet.Manuals
		case "tftp":
			target.FoundPorts[index].Service.Scans = scanConfig.TFTP.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.TFTP.Manuals
		case "vnc":
			target.FoundPorts[index].Service.Scans = scanConfig.VNC.Scans
			target.FoundPorts[index].Service.Manuals = scanConfig.VNC.Manuals
		}
	}

}

func runCommand(enumJobs <-chan map[string]string, outStream chan<- map[string]interface{}, errStream chan<- map[string]interface{}, target *Target, wg *sync.WaitGroup) {
	defer wg.Done()

	ip := target.IP

	for job := range enumJobs {
		for name, command := range job {
			var out bytes.Buffer
			var stderr bytes.Buffer
			progAndArgs := strings.Split(command, " ")

			prog := progAndArgs[0]
			tmpArgs := progAndArgs[1:]
			args := []string{}
			if prog == "bash" {
				opt := []string{tmpArgs[0]}
				args = append(opt)
				args = append(args, strings.Join(tmpArgs[1:], " "))
			} else {
				args = tmpArgs
			}
			//fmt.Printf("Running: %v %v\n", prog, args)
			cmd := exec.Command(prog, args...)
			cmd.Stdout = &out
			cmd.Stderr = &stderr

			err := cmd.Start()
			if err != nil {
				log.Println("Could not start" + prog)
				log.Println(err)
			}

			// Kill process if it is not done in a timely manner
			// Set timeout to 300 sec or more
			if timeout < 300 {
				timeout = 300
			}

			// Wait for either the done channel or the timeout to expire
			done := make(chan error, 1)
			go func() {
				done <- cmd.Wait()
			}()

			select {
			case <-time.After(timeout * time.Second):
				err = cmd.Process.Kill()
				if err != nil {
					log.Println("Failed to kill", prog)
					log.Fatal(err)
				} else {
					log.Println(prog + " finished successfully on " + ip)
				}
			case err = <-done:
				if err != nil {
					//log.Println(prog + " finished with error(s) on " + ip)
					//log.Println(cmd.Stderr)
					cmdOutput := make(map[string]interface{})
					cmdErr := make(map[string]interface{})
					cmdOutput[name] = cmd.Stdout
					cmdErr[name] = cmd.Stderr
					outStream <- cmdOutput
					errStream <- cmdErr
				} else {
					log.Println(prog + " finished on " + ip)
					cmdOutput := make(map[string]interface{})
					cmdOutput[name] = cmd.Stdout
					outStream <- cmdOutput
				}

			}
		}

	}
}

func writeFile(streamType string, outStream <-chan map[string]interface{}, target *Target, wg *sync.WaitGroup) {
	defer wg.Done()
	for outContent := range outStream {
		for name, output := range outContent {
			switch name {
			case "manual":
				fmt.Println(name, output)
				output = output.(string) + "\n"
			default:
				continue
			}
			outFilename := name + "_" + streamType + "_" + target.IP + ".txt"
			outputDir := cwd + "/" + target.IP + "/"
			// Crete the files or append if they already exist
			outFile, err := os.OpenFile(outputDir+outFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0755)
			if err != nil {
				log.Fatal("Could not create the output file " + outputDir + outFilename)
			}
			_, err = outFile.WriteString(fmt.Sprint(output))
			if err != nil {
				log.Println("Could not write to out file" + outputDir + outFilename)
				log.Fatal(err)
			}
		}
	}
}

func getType(myvar interface{}) string {
	if t := reflect.TypeOf(myvar); t.Kind() == reflect.Ptr {
		return "*" + t.Elem().Name()
	} else {
		return t.Name()
	}
}
