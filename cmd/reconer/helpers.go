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

	"gopkg.in/getlantern/deepcopy.v1"
)

// Sets the directory structure for each IP address
func setDirStruct(target *Target) {
	dirs := []string{"loot", "exploit", "www", "scans/xml"}
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
		log.Printf("There are %d goroutines running\n", runtime.NumGoroutine())
	}
}

func replacePlaceHolders(command string, port string, ip string, protocol string, directory string, hasSSL bool) string {
	patterns := [8]string{
		"{port}",
		"{address}",
		"{protocol}",
		"{scandir}",
		"{scheme}",
		"{usernameWordlist}",
		"{passwordWordlist}",
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
		for j, scan := range target.FoundPorts[i].Service.Scans {
			cmd := replacePlaceHolders(scan.Command, service.ScanPort, target.IP, service.Protocol, cwd+"/"+target.IP+"/scans", service.HasSSL)
			target.FoundPorts[i].Service.Scans[j].Command = cmd
		}
	}

	// Replace the manual commands

	for i, service := range target.FoundPorts {
		for j := range target.FoundPorts[i].Service.Manuals {
			for k, command := range target.FoundPorts[i].Service.Manuals[j].Commands {
				cmd := replacePlaceHolders(command, service.ScanPort, target.IP, service.Protocol, cwd+"/"+target.IP+"/", service.HasSSL)
				target.FoundPorts[i].Service.Manuals[j].Commands[k] = cmd
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
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.Cassandra.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.Cassandra.Manuals)
		case "ipp":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.Cups.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.Cups.Manuals)
		case "distccd":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.Distcc.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.Distcc.Manuals)
		case "domain":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.Finger.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.Finger.Manuals)
		case "ftp", "ftp-data":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.FTP.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.FTP.Manuals)
		case "http", "https", "ssl/http":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.HTTP.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.HTTP.Manuals)
		case "imap":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.IMAP.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.IMAP.Manuals)
		case "kerberos", "kpasswd":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.Kerberos.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.Kerberos.Manuals)
		case "ldap":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.LDAP.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.LDAP.Manuals)
		case "mongod":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.Mongodb.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.Mongodb.Manuals)
		case "mssql", "ms-sql":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.MSSQL.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.MSSQL.Manuals)
		case "mysql":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.MYSQL.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.MYSQL.Manuals)
		case "nfs", "rpcbind":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.NFS.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.NFS.Manuals)
		case "nntp":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.NTP.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.NTP.Manuals)
		case "oracle":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.Oracle.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.Oracle.Manuals)
		case "pop3":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.POP3.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.POP3.Manuals)
		case "rdp", "ms-wbt-server", "ms-term-serv":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.RDP.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.RDP.Manuals)
		case "java-rmi", "rmiregistry":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.RMI.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.RMI.Manuals)
		case "msrpc", "erpc":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.RPC.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.RPC.Manuals)
		case "asterisk":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.SIP.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.SIP.Manuals)
		case "ssh":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.SSH.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.SSH.Manuals)
		case "smb", "microsoft-ds", "netbios":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.SMB.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.SMB.Manuals)
		case "smtp":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.SMTP.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.SMTP.Manuals)
		case "snmp":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.SNMP.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.SNMP.Manuals)
		case "telent":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.Telnet.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.Telnet.Manuals)
		case "tftp":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.TFTP.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.TFTP.Manuals)
		case "vnc":
			deepcopy.Copy(&target.FoundPorts[index].Service.Scans, scanConfig.VNC.Scans)
			deepcopy.Copy(&target.FoundPorts[index].Service.Manuals, scanConfig.VNC.Manuals)
		}
	}

}

func removeQuotes(s string) string {
	if len(s) > 0 && s[0] == '"' {
		s = s[1:]
	}
	if len(s) > 0 && s[len(s)-1] == '"' {
		s = s[:len(s)-1]
	}
	return s
}

func splitCommand(command string) []string {
	quoted := false
	a := strings.FieldsFunc(command, func(r rune) bool {
		if r == '"' {
			quoted = !quoted
		}
		return !quoted && r == ' '
	})
	for i, s := range a {
		a[i] = removeQuotes(s)
	}
	return a
}

func runCommand(enumJobs <-chan map[string]string, outStream chan<- map[string]interface{}, errStream chan<- map[string]interface{}, target *Target, wg *sync.WaitGroup) {
	defer wg.Done()

	ip := target.IP
	for job := range enumJobs {
		for name, command := range job {
			var out bytes.Buffer
			var stderr bytes.Buffer
			progAndArgs := splitCommand(command)

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
			//log.Printf("Running: %v %v\n", prog, args)
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
					log.Println(prog + " timed out " + ip)
				}
			case err = <-done:
				if err != nil {
					cmdOutput := make(map[string]interface{})
					cmdErr := make(map[string]interface{})
					cmdOutput[name] = cmd.Stdout
					cmdErr[name] = cmd.Stderr
					outStream <- cmdOutput
					errStream <- cmdErr
				} else {
					//					log.Println(prog + args[0] + " finished on " + ip)
					cmdOutput := make(map[string]interface{})
					cmdOutput[name] = cmd.Stdout
					outStream <- cmdOutput
				}

			}
		}

	}
}

func generateServiceSummary(target *Target) {
	output := "# " + target.IP + " #\n\n"
	output = output + "| Port | Service | Version |\n"
	output = output + "|------|---------|---------|"
	for _, service := range target.FoundPorts {
		output = output + "\n| " + service.ScanPort + " | " + service.ServiceName + " | " + service.Version + " |"
	}
	outDir := cwd + "/" + target.IP + "/"
	filename := "summary.md"
	simpleWriteFile(outDir, output, filename)
}

func writeFile(streamType string, outStream <-chan map[string]interface{}, target *Target, wg *sync.WaitGroup) {
	defer wg.Done()
	for outContent := range outStream {
		for name, output := range outContent {
			if name == "manual" {
				output = output.(string) + "\n"
			}
			outFilename := name + ".txt"
			if streamType == "err" {
				outFilename = "err_" + outFilename
			}
			outputDir := cwd + "/" + target.IP + "/scans/"
			// Crete the files or append if they already exist
			outFile, err := os.OpenFile(outputDir+outFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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

func simpleWriteFile(outputDir string, output string, filename string) {
	outFile, err := os.OpenFile(outputDir+filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("Could not load file:", outputDir+filename, err)
	}
	_, err = outFile.WriteString(output)
	if err != nil {
		log.Fatal("Could not write to file", outputDir+filename, err)
	}
}

func getType(myvar interface{}) string {
	if t := reflect.TypeOf(myvar); t.Kind() == reflect.Ptr {
		return "*" + t.Elem().Name()
	} else {
		return t.Name()
	}
}
