# Reconer
This tool is provided as is and I provide no guarantees on its effectiveness.

# Introduction
This tool was my lame attempt to rebuild [autorecon](https://github.com/Tib3rius/AutoRecon) by Tib3rius in go for my OSCP exam. To be honest, I would not recommend using this tool as it it not full featured and it probably will not be maintained. For fun and experience, I am just dropping this out in the world for anyone who wants to play with it and torture themselves. 

# Basic Usage
```bash
Usage of reconer:
-c: set how many IPs will be processed concurrently
-e: Set how many scans can happen concurrently for each IP
-hb: Set the heartbeat interval
-i: A list of IP addresses given at the commandline separated by a comma
-I: A list of IP addresses separated by a line break
-run-udp-scan: Run UDP top 20 scan -run-udp-scan=true
-run-vuln-scan: Run Vul scripts on TCP ports -run-udp-scan=true
-t: Set the timeout in seconds
-v: Set the verbosity of the output 0 or 1
```
You will need to have two TOML configuration files in the directory you are running reconer from. Example TOML configurations can be found in the cmd/reconer directory of this repo. At this time, the tool will only run the commands under `[default]` and does not use the pattern variable. 

# Installation
If you do not have GO installed, you should do that first. [Intall GO](https://golang.org/doc/install). 

You should be able to then run:
```bash
go get -v github.com/man715/reconer/cmd/reconer
```
This will install the reconer tool but not the TOML configurations. You will need to download them or build them yourself and put them in the directory you are running the tool from. Yes, this is not convenient as you have to have multiple configuration files or you need to keep moving your configuration files around.

This will install reconer at `/home/<USERNAME>/go/bin/` so you will need to make sure that is in your PATH.

# Questions
If you have any questions, feel free to ask. If you want to work on this tool feel free to fork it and submit pull requests but I really don't know a whole lot about development or Git in general so it may take me some time to figure it out.
