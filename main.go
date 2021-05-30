package main

import (
    "bytes"
    "fmt"
    "flag"
    "strings"
    "strconv"
    "time"
    "log"
    "io/ioutil"
    "os"
    "os/exec"
    "sync"
    "github.com/Ullaakut/nmap"
)

func main() {
    // check if this is running as root
    //if os.Geteuid() != 0 {
    //    panic("You need to run this as root, sorry!")
    //}
    var wg sync.WaitGroup

    // Get the current working directory
    cwd, err := os.Getwd()
    if err != nil {
        panic(err)
    }

    var concurrency int
    var enumConcurrency int
    var timeout int
    flag.IntVar(&concurrency,"c", 20, "Set how many IPs will be processed concurrently")
    flag.IntVar(&enumConcurrency,"e", 5, "Set how many scans can happen concurrently for each IP")
    ipList := flag.String("i", "", "A list of IP addresses given at the commandline separated by a comma")
    flag.IntVar(&timeout, "t", 60, "Set the timeout in seconds")
    ipFileList := flag.String("I", "", "A list of IP addresses separated by a line break.")

    flag.Parse()

    // Check that there is a list of IPs to use
    if *ipFileList == "" && *ipList == "" {
        panic("[!] A list of IPs is required")
    }

    // Make the channels buffer size be able to hold up to an entire IP range
    jobs := make(chan string, 255)
    results := make(chan string, 255)

    // Create the workers
    for i := 0; i < concurrency; i++ {
        go reconWorker(cwd, jobs, results, enumConcurrency, &wg, time.Duration(timeout))
    }
    var ips []string
    // Create the list of jobs
    if  *ipList != ""{
        ips = strings.Split(*ipList, ",")
    } else {
        // Read the file in
        fileBytes, err := ioutil.ReadFile(*ipFileList)
        // Error Handling
        if err != nil {
            fmt.Println(err)
            os.Exit(1)
        }
        // Make the list of jobs
        ips = strings.Split(string(fileBytes), "\n")
        // Clean up the list to remove the last empty space
        ips = ips[:len(ips)-1]
    }

    // Create the jobs
    for j := range ips {
        jobs <- ips[j]
    }
    close(jobs)

    // Get the Results
    for j := range ips {
        fmt.Println("IP:", ips[j], <-results)
    }

    wg.Wait()

}

func reconWorker(cwd string, jobs <-chan string, results chan<- string, enumConcurrency int, wg *sync.WaitGroup, timeout time.Duration) {
    wg.Add(1)
    defer wg.Done()
    for n := range jobs {
        // Set up the basic directory structure for the IP
        setDirStruct(cwd, n)

        // Start nmap scans
        nmapFile := cwd + "/" + n + "/nmap/tcpAllPorts-defaultScripts.nmap"

        // Scan All TCP ports
        openPorts, hostAddress,err := runNmapTcp(n, "445,80", nmapFile)
        if err != nil {
            panic(err)
        }

        // Set up Channels for the enum workers
        enumJobs := make(chan []string, 10)
        enumResults := make(chan string, 10)

        // Set up wait group for enum workers
        var wg2 sync.WaitGroup

        // Create enumWorkers
        for i := 0; i < enumConcurrency; i ++ {
            go enumWorker(cwd, hostAddress, enumJobs, enumResults, &wg2, timeout)
        }

        var enumList []string

        // Iterate through each port that was found open
        for _, port := range openPorts {

            // Convert the port.ID to a string to be evaluated
            portNumber := strconv.Itoa(int(port.ID))
            portState := port.State.String()

            // Populate the enumJobs channel
            if portNumber == "80" && portState == "open" {
                enumList = append(enumList, "ffuf," + portNumber)
                enumList = append(enumList, "whatweb," + portNumber)
                enumList = append(enumList, "nikto," + portNumber)
            } else if portNumber == "443" && portState == "open" {
                enumList = append(enumList, "ffuf," + portNumber)
                enumList = append(enumList, "whatweb," + portNumber)
                enumList = append(enumList, "nikto," + portNumber)
            } else if portNumber == "445" && portState == "open" {
                fmt.Println("Setting SMB jobs for " + hostAddress)
                enumList  = append(enumList, "smbmap," + portNumber)
                enumList = append(enumList, "smbclient," + portNumber)
            }
        }

        // Set jobs that will run on all hosts
        enumList = append(enumList,"enum4linux,-")


        // Add the jobs to the que
        for _, j := range enumList {
            job := strings.Split(j, ",")
            enumJobs <- job
        }

        // Close the enumJobs channel because all jobs should be loaded
        close(enumJobs)

        for range enumList {
            _ = <-enumResults
        }

        // Wait for all of the IP jobs to be done before finishing
        wg2.Wait()

        results <- "Is finished."
    }
}

func enumWorker(cwd string, ip string, jobs <-chan []string, results chan<- string, wg *sync.WaitGroup, timeout time.Duration) {
    // Add one to the wait group for this worker
    wg.Add(1)

    // Close the wait group associated with this worker.
    defer wg.Done()

    // Start processing the jobs based on the job type
    var portNumber string
    for job := range jobs {
        portNumber = job[1]

        if job[0] == "enum4linux" {
            // run enum4linux
            runE4L(cwd, ip, "result.txt")
        } else if job[0] == "ffuf" {
            // run ffuf
            runFfuf(cwd, ip, portNumber, portNumber + "-root.csv")
        } else if job[0] == "whatweb" {
            //run whatweb
            runWhatWeb(cwd, ip, portNumber, "results.txt")
        } else if job[0] == "nikto" {
            // run nikto
            runNikto(cwd, ip, portNumber, "result.txt")
        } else if job[0] == "onesixtyone" {
            // run onesixtyone
        } else if job[0] == "smbmap" {
            // run smbmap
            runSmbmap(cwd, ip, "results.txt", timeout)
        } else {
            // run smbclient
            runSmbclient(cwd, ip, "results.txt", timeout)
        }
    }

    results <- "Done"
}


func runFfuf(cwd string, ip string, port string, fileName string) string {
    // Create the directory to store the results in
    err := os.MkdirAll(ip + "/ffuf", 0755)
    url := "http://" + ip + "/FUZZ"
    wordlist := "/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt"
    ffufFile := "ffuf/" + fileName
    ffufCommand := "ffuf -u " + url + " -w " + wordlist + " -o " + cwd + "/" + ip + "/" + ffufFile
    ffufArgs := strings.Split(ffufCommand, " ")

    var out bytes.Buffer
    var stderr bytes.Buffer
    cmd := exec.Command(ffufArgs[0], ffufArgs[1:]...)

    cmd.Stdout = &out
    cmd.Stderr = &stderr
    err = cmd.Run()
    if err != nil {
        fmt.Println(fmt.Sprint(err) + ": " +stderr.String())
        panic("ffuf failed")
    }

    return out.String()
}

func runSmbclient(cwd string, ip string, fileName string, timeout time.Duration) string {
    fmt.Println("RUNNING SMBCLIENT ON", ip)
    err := os.MkdirAll(ip + "/smbclient", 0755)
    if err != nil {
        panic(err)
    }

    smbclientFile := cwd + "/" + ip + "/smbclient/" + fileName
    smbclientCommand := "smbclient --no-pass -L " + ip
    smbclientArgs := strings.Split(smbclientCommand, " ")

    var out bytes.Buffer
    var stderr bytes.Buffer

    cmd := exec.Command(smbclientArgs[0], smbclientArgs[1:]...)

    cmd.Stdout = &out
    cmd.Stderr = &stderr

    if err := cmd.Start(); err != nil {
        log.Fatal(err)
    }

    // Wait for the process to finish or kill it after timeout
    done := make(chan error, 1)
    go func() {
        done <- cmd.Wait()
    }()

    select {
    case <-time.After(timeout * time.Second):
        if err := cmd.Process.Kill(); err != nil {
            log.Fatal("failed to kill process: ", err)
        }
        log.Println("smbclient killed as timeout reached on", ip)
    case err := <-done:
        if err != nil {
            log.Println("smbclient error for IP " + ip + ": " + out.String())
            //fmt.Println(out.String())
            //log.Printf("smbclient finsihed on %s with error = %v", ip, err)
        } else {
            log.Print("smbclient finished successfully on ", ip)
        }
    }
    outFile, err := os.Create(smbclientFile)
    if err != nil {
        panic(err)
    }
    defer outFile.Close()
    _, err = outFile.WriteString(out.String())
    if err != nil {
        panic(err)
    }

    return out.String()
}

func runSmbmap(cwd string, ip string, fileName string, timeout time.Duration) string {
    fmt.Println("RUNNING SMBMAP ON", ip)
    err := os.MkdirAll(ip + "/smbmap", 0755)
    if err != nil {
        panic(err)
    }

    smbmapFile := cwd + "/" + ip + "/smbmap/" + fileName
    smbmapCommand := "smbmap -u \"\" -p \"\" -H " + ip
    smbmapArgs := strings.Split(smbmapCommand, " ")

    var out bytes.Buffer
    var stderr bytes.Buffer

    cmd := exec.Command(smbmapArgs[0], smbmapArgs[1:]...)

    cmd.Stdout = &out
    cmd.Stderr = &stderr

    if err := cmd.Start(); err != nil {
        log.Fatal(err)
    }
    // Wait for the process to finish or kill it after timeout
    done := make(chan error, 1)
    go func() {
        done <- cmd.Wait()
    }()
    select {
    case <-time.After(timeout * time.Second):
        if err := cmd.Process.Kill(); err != nil {
            log.Fatal("failed to kill process: ", err)
        }
        log.Println("[!] smbmap killed as timeout reached on ", ip)
    case err := <-done:
        if err != nil {
            log.Printf("[!] smbmap finished on %s with error = %v", ip, err)
        } else {
            log.Print("smbmap on " + ip + " finished successfully")
        }
    }

    outFile, err := os.Create(smbmapFile)
    if err != nil {
        panic(err)
    }
    defer outFile.Close()
    _, err = outFile.WriteString(out.String())
    if err != nil {
        panic(err)
    }

    return out.String()
}

func runE4L(cwd string, ip string, fileName string) string {
    err := os.MkdirAll(ip + "/e4l", 0755)
    if err != nil {
        panic(err)
    }

    e4lFile := cwd + "/" + ip + "/e4l/" + fileName
    e4lCommand := "enum4linux " + ip
    e4lArgs := strings.Split(e4lCommand, " ")

    var out bytes.Buffer
    var stderr bytes.Buffer

    cmd := exec.Command(e4lArgs[0], e4lArgs[1:]...)

    cmd.Stdout = &out
    cmd.Stderr = &stderr
    err = cmd.Run()
    if err != nil {
        log.Println("enum4linux had an error: " + fmt.Sprint(err) + ": " + stderr.String())
    }

    outFile, err := os.Create(e4lFile)
    if err != nil {
        panic(err)
    }
    defer outFile.Close()
    _, err = outFile.WriteString(out.String())
    if err != nil {
        panic(err)
    }

    return out.String()
}

func runNikto(cwd string, ip string, port string, fileName string) string {
    err := os.MkdirAll(ip + "/nikto", 0755)
    if err != nil {
        panic(err)
    }

    niktoFile := cwd + "/" + ip + "/nikto/" + fileName

    var protocol string
    if  port == "80" {
        protocol = "http://"
    } else {
        protocol = "https://"
    }
    url := protocol + ip
    niktoCommand := "nikto -host=" + url
    niktoArgs := strings.Split(niktoCommand, " ")

    var out bytes.Buffer
    var stderr bytes.Buffer

    cmd := exec.Command(niktoArgs[0], niktoArgs[1:]...)

    cmd.Stdout = &out
    cmd.Stderr = &stderr
    err = cmd.Run()
    if err != nil {
        fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
        panic("nikto failed")
    }
    outFile, err := os.Create(niktoFile)
    if err != nil {
        panic(err)
    }
    defer outFile.Close()
    _, err = outFile.WriteString(out.String())
    if err != nil {
        panic(err)
    }

    return out.String()
}

func runWhatWeb(cwd string, ip string, port string, fileName string) string {
    err :=  os.MkdirAll(ip + "/whatweb", 0755)
    whatWebFile := cwd + "/" + ip + "/whatweb/" + fileName
    var protocol string
    if port == "80" {
        protocol = "http://"
    } else {
        protocol = "https://"
    }
    url := protocol + ip
    whatWebCommand := "whatweb -a 3 " + url
    whatWebArgs := strings.Split(whatWebCommand, " ")

    var out bytes.Buffer
    var stderr bytes.Buffer
    cmd := exec.Command(whatWebArgs[0], whatWebArgs[1:]...)

    cmd.Stdout = &out
    cmd.Stderr = &stderr
    err = cmd.Run()
    if err != nil {
        fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
        panic("whatweb failed")
    }
    outFile, err := os.Create(whatWebFile)
    if err != nil {
        panic(err)
    }
    defer outFile.Close()
    _, err = outFile.WriteString(out.String())
    if err != nil {
        panic(err)
    }

    return out.String()
}

func setDirStruct(p string, ip string) {
    // Create the directories in the dirs slice
    dirs := []string{"loot", "exploit", "www", "nmap"}
    for dir := range dirs {
        // os.MkdirAll makes directories in the current working directory.
        err := os.MkdirAll(string(ip) +"/" + dirs[dir], 0755)
        if err != nil {
            panic(err)
        }
    }

}

func runNmapTcp(ip string, ports string, outputName string) ([]nmap.Port, string, error) {

    //Set all ports as the default scan range
    if ports == "" {
        ports = "-65535"
    }

    var openPorts []nmap.Port
    var hostAddress nmap.Address

    nmapScanner, err := nmap.NewScanner(
        nmap.WithTargets(ip),
        nmap.WithPorts(ports),
        nmap.WithServiceInfo(),
        nmap.WithDefaultScript(),
        nmap.WithNmapOutput(outputName),
        nmap.WithSkipHostDiscovery(),
        nmap.WithConnectScan(),
    )
    if err != nil {
        return nil, "",err
    }
    result, warnings, err := nmapScanner.Run()
    if err != nil {
        return nil, "", err
    }
    if warnings != nil {
        //fmt.Println(warnings)
    }
    for _, host := range result.Hosts{
        if len(host.Ports) == 0 || len(host.Addresses) == 0 {
            fmt.Println("no host")
            continue
        }

        openPorts = host.Ports
        hostAddress = host.Addresses[0]
    }
    if hostAddress.String() == "" {
        return nil, "", nil
    }
    return openPorts, hostAddress.String(), err
}

func runNmapTopUDP(ip string, top int, outputName string) ([]nmap.Port, nmap.Address, error) {


    var openPorts []nmap.Port
    var hostAddress nmap.Address

    nmapScanner, err := nmap.NewScanner(
        nmap.WithTargets(ip),
        nmap.WithServiceInfo(),
        nmap.WithNmapOutput(outputName),
        nmap.WithUDPScan(),
        nmap.WithMostCommonPorts(top),
    )
    if err != nil {
        return openPorts, hostAddress,err
    }
    result, warnings, err := nmapScanner.Run()
    if err != nil {
        return openPorts, hostAddress,err
    }
    if warnings != nil {
        fmt.Println(warnings)
    }
    for _, host := range result.Hosts{
        if len(host.Ports) == 0 || len(host.Addresses) == 0 {
            continue
        }

        openPorts = host.Ports
        hostAddress = host.Addresses[0]
    }
    fmt.Println(openPorts)
    panic("DELETE ME")
    return openPorts, hostAddress,err
}

