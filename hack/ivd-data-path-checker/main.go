package main

import (
	"github.com/sirupsen/logrus"
	"github.com/vmware-tanzu/astrolabe/pkg/astrolabe"
	"github.com/vmware-tanzu/astrolabe/pkg/server"
	"os"
	"time"
)

func main() {
	// step 0: set up the environment
	logger := logrus.New()
	formatter := new(logrus.TextFormatter)
	formatter.TimestampFormat = time.RFC3339Nano
	formatter.FullTimestamp = true
	logger.SetFormatter(formatter)

	configFilePath, exist := os.LookupEnv("CONFIG_FILE_PATH")
	if !exist {
		logger.Error("CONFIG_FILE_PATH is not set")
		return
	}

	// step 1: set up astrolabe PEM from config directory with IVD config info
	pem := server.NewProtectedEntityManager(configFilePath)
	if pem == nil {
		logger.Error("Unexpected config file provided")
		return
	}

	ivdPETM := pem.GetProtectedEntityTypeManager(astrolabe.IvdPEType)
	if ivdPETM == nil {
		logger.Error("Unexpected config file name. Expected: %s.pe.json", astrolabe.IvdPEType)
		return
	}

	// step 2: create a 20 MB IVD from IVD PETM


    // step 3: Copy it from IVD PE in vSphere to a local zip file
	// step 4: Copy it from a local zip file to IVD PE in vSphere
	// test completed
}
