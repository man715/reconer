package main

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

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

