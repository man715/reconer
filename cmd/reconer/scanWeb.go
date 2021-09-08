package main

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// nikto
func runNikto(ip string, portService string, portNumber string, fileName string) {
	err = os.MkdirAll(ip+"/nikto", 0755)
	if err != nil {
		log.Fatal("Could not create directory for nikto: ", err)
	}

	outputFile := cwd + "/" + ip + "/nikto/" + fileName

  protocol := portService + "://"
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

// whatweb
func runWhatweb(ip string, portService string, portNumber string, fileName string) {
	err = os.MkdirAll(ip+"/whatweb", 0755)
	if err != nil {
		log.Fatal("Could not create directory for whatweb: ", err)
	}
	outputFile := cwd + "/" + ip + "/whatweb/" + fileName

  protocol := portService + "://"
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

// ffuf
func runFfuf(ip string, portService, portNumber string, fileName string) {
	// create teh directory to store teh results in

	err = os.MkdirAll(ip+"/ffuf", 0755)
	if err != nil {
		log.Fatal("Could not create the directory for ffuf: ", err)
	}

  protocol := portService +"://"

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
