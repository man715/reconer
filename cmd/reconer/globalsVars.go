package main

import (
	"time"
)

// Global Variables
var heartbeatInterval time.Duration
var timeout time.Duration
var cwd string
var err error
var verbose int
var runVuln bool
var runUdp bool
var scanConfig ScanConfig
