package main

import (
	"sync"
)

// Worker for each IP address to have recon done on
func targetWorker(jobs <-chan *Target, enumConcurrency int, wg *sync.WaitGroup) {
	defer wg.Done()
	for target := range jobs {
		setDirStruct(target)
		scanDir := cwd + "/" + target.IP + "/scans/"

		var writerWg sync.WaitGroup
		writerWg.Add(2)
		outStream := make(chan map[string]interface{}, 20)
		errStream := make(chan map[string]interface{}, 20)
		go writeFile("results", outStream, target, &writerWg)
		go writeFile("err", errStream, target, &writerWg)

		for _, scan := range portScanConfig.Default.Scans {
			cmd := replacePlaceHolders(scan.Command, "", target.IP, "", scanDir, false)
			runNmap(target, cmd, scan.Name, scanDir)
		}

		generateServiceSummary(target)

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
			writeDescription := make(map[string]interface{})
			writeDescription[filename] = "\n\n********************Description*******************\n" + manualCommands.Description + "\n**************************************************"

			manualStream <- writeDescription
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
