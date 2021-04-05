package main

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vmware-tanzu/astrolabe/pkg/astrolabe"
	"github.com/vmware-tanzu/astrolabe/pkg/server"
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
	pem := server.NewProtectedEntityManager(configFilePath, logrus.New())
	if pem == nil {
		logger.Error("Unexpected config file provided")
		return
	}

	ivdPETM := pem.GetProtectedEntityTypeManager(astrolabe.IvdPEType)
	if ivdPETM == nil {
		logger.Error("Unexpected config file name. Expected: %s.pe.json", astrolabe.IvdPEType)
		return
	}

	//// step 2: create a VM and power it on, then create a 50 MB IVD and attach it to the VM.
	//ctx := context.Background()
	//vCenterClient := ivd.GetVCenterUtil(ivdPETM.(*ivd.IVDProtectedEntityTypeManager)).Client.Client
	//
	//vmMo, err := ivd.CreateVmUtil(ctx, vCenterClient, logger)
	//if err != nil {
	//	logger.Errorf("Failed to create a VM with err: %v", err)
	//	return
	//}
	//vmRef := vmMo.Reference()
	//defer func() {
	//	if err := ivd.DeleteVmUtil(ctx, vCenterClient, vmRef, logger); err != nil {
	//		return
	//	}
	//}()
	//
	//if err := ivd.PoweronVmUtil(ctx, vCenterClient, vmRef); err != nil {
	//	logger.WithError(err).Errorf("Failed to power on VM %v", vmRef)
	//	return
	//}
	//logger.Debugf("VM, %v, is powered on", vmRef)
	//
	//defer func() {
	//	if err := ivd.PoweroffVmUtil(ctx, vCenterClient, vmRef); err != nil {
	//		logger.WithError(err).Errorf("Failed to power off VM %v", vmRef)
	//		return
	//	}
	//	logger.Debugf("VM, %v, is powered off", vmRef)
	//}()
	//
	//// get vm host
	//var vmHostSystem *object.HostSystem
	//if vmHostSystem, err = vmMo.HostSystem(ctx); err != nil {
	//	logger.Errorf("Failed to get VM HostSystem object from VM managed object %v with err: %v", vmRef, err)
	//	return
	//}
	//
	//// pick an ivd datastore that is accessible from the vm host and create an ivd on it
	//ivdDs, err := ivd.PickOneAccessibleDatastoreFromHosts(ctx, vCenterClient, []types.ManagedObjectReference{vmHostSystem.Reference()}, nil, logger)
	//if err != nil {
	//	return
	//}
	//createSpec := ivd.GetCreateSpec(ivd.GetRandomName("ivd", 6), 50, ivdDs, ivd.GetProfileSpecs(""))
	//ivdId, err := ivd.CreateDiskUtil(ctx, ivdPETM.(*ivd.IVDProtectedEntityTypeManager), createSpec, logger)
	//if err != nil {
	//	logger.Errorf("Failed to create a disk with err: %v", err)
	//	return
	//}
	//
	//defer func() {
	//	if err := ivd.DeleteDiskUtil(ctx, ivdPETM.(*ivd.IVDProtectedEntityTypeManager), ivdId); err != nil {
	//		logger.Errorf("Failed to delete the disk %v with err: %v", ivdId.Id, err)
	//		return
	//	}
	//}()
	//
	//// attach disk to vm
	//if err := ivd.AttachDiskUtil(ctx, vCenterClient, vmRef, ivdId, ivdDs); err != nil {
	//	logger.Errorf("Failed to attach the disk %v to the VM %v with err: %v", ivdId.Id, vmRef, err)
	//	return
	//}
	//
	//defer func() {
	//	if err := ivd.DetachDiskUtil(ctx, vCenterClient, vmRef, ivdId); err != nil {
	//		logger.Errorf("Failed to detach the disk %v from the VM %v with err: %v", ivdId.Id, vmRef, err)
	//		return
	//	}
	//}()

	// TODO: step 3: create a snapshot on the IVD


	// TODO: step 4: copy IVD snapshot to a local zip file

	// TODO: step 5: create a new IVD

	// TODO: step 6: overwrite the new IVD with data from the local zip file

	// test completed
}
