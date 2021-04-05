/*
 * Copyright 2019 the Astrolabe contributors
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ivd

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/kr/pretty"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vmware-tanzu/astrolabe/pkg/astrolabe"
	"github.com/vmware-tanzu/astrolabe/pkg/common/vsphere"
	"github.com/vmware-tanzu/astrolabe/pkg/s3repository"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/pbm"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/methods"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"
	"math"
	"math/rand"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProtectedEntityIDFromString(t *testing.T) {

}

const (
	MaxNumOfIVDs = 15
)

func TestSnapshotOpsUnderRaceCondition(t *testing.T) {
	// #0: Setup the environment
	// Prerequisite: export ASTROLABE_VC_URL='https://<VC USER>:<VC USER PASSWORD>@<VC IP>/sdk'
	u, exist := os.LookupEnv("ASTROLABE_VC_URL")
	if !exist {
		t.Skipf("ASTROLABE_VC_URL is not set")
	}

	nIVDs := 5
	nIVDsStr, ok := os.LookupEnv("NUM_OF_IVD")
	if ok {
		nIVDsInt, err := strconv.Atoi(nIVDsStr)
		if err == nil && nIVDsInt > 0 && nIVDsInt <= MaxNumOfIVDs {
			nIVDs = nIVDsInt
		}
	}

	vcUrl, err := soap.ParseURL(u)
	if err != nil {
		t.Skipf("Failed to parse the env variable, ASTROLABE_VC_URL, with err: %v", err)
	}

	ctx := context.Background()
	logger := logrus.New()
	formatter := new(logrus.TextFormatter)
	formatter.TimestampFormat = time.RFC3339Nano
	formatter.FullTimestamp = true
	logger.SetFormatter(formatter)
	logger.SetLevel(logrus.DebugLevel)

	params := getIVDConfigParams(vcUrl)
	ivdPETM, err := NewIVDProtectedEntityTypeManager(params, astrolabe.S3Config{URLBase: "VOID_URL"}, logger)
	if err != nil {
		t.Skipf("Failed to get a new ivd PETM: %v", err)
	}

	virtualCenter := ivdPETM.vcenter

	vmHost, err := pickOneHost(ctx, virtualCenter.Client.Client, logger)
	if err != nil {
		t.Skipf("Failed to find a host for VM creation with err: %v", err)
	}

	// #1: Create a few of IVDs
	ivdDs, err := pickOneAccessibleDatastoreFromHosts(ctx, virtualCenter.Client.Client, []types.ManagedObjectReference{vmHost}, nil, logger)
	if err != nil {
		t.Skipf("Failed to find an accessible datastore from VM host %v with err: %v", vmHost, err)
	}

	logger.Infof("Step 1: Creating %v IVDs", nIVDs)
	var ivdIds []types.ID
	for i := 0; i < nIVDs; i++ {
		createSpec := getCreateSpec(getRandomName("ivd", 6), 50, ivdDs, nil)
		diskID, err := createDisk(ctx, ivdPETM, createSpec, logger)
		if err != nil {
			t.Skipf("Failed to create IVD with err: %v", err)
		}
		ivdIds = append(ivdIds, diskID)
	}

	if ivdIds == nil {
		t.Skipf("Failed to create the list of ivds as expected")
	}

	defer func() {
		for i := 0; i < nIVDs; i++ {
			if err := deleteDisk(ctx, ivdPETM, ivdIds[i], logger); err != nil {
				t.Skipf("Failed to delete IVD %v with err: %v", ivdIds[i].Id, err)
			}
		}
	}()

	// #2: Create a VM
	logger.Info("Step 1: Creating a VM")
	vmMo, err := createDummyVm(ctx, virtualCenter.Client.Client, vmHost, nil, logger)
	if err != nil {
		t.Skipf("Failed to create a VM with err: %v", err)
	}
	vmRef := vmMo.Reference()
	defer func() {
		if err := deleteVm(ctx, virtualCenter.Client.Client, vmRef, nil); err != nil {
			t.Skipf("Failed to delete VM %v with err: %v", vmRef, err)
		}
	}()

	// #3: Attach those IVDs to the VM
	logger.Infof("Step 3: Attaching IVDs to VM %v", vmRef)
	for i := 0; i < nIVDs; i++ {
		err = attachDisk(ctx, virtualCenter.Client.Client, vmRef.Reference(), ivdIds[i], ivdDs.Reference(), nil)
		if err != nil {
			t.Skipf("Failed to attach ivd, %v, to, VM, %v with err: %v", ivdIds[i].Id, vmRef, err)
		}

		logger.Debugf("IVD, %v, attached to VM, %v", ivdIds[i].Id, vmRef)
	}

	defer func() {
		for i := 0; i < nIVDs; i++ {
			err = detachDisk(ctx, virtualCenter.Client.Client, vmRef.Reference(), ivdIds[i], nil)
			if err != nil {
				t.Skipf("Failed to detach ivd, %v, to, VM, %v with err: %v", ivdIds[i].Id, vmRef, err)
			}

			logger.Debugf("IVD, %v, detached from VM, %v", ivdIds[i].Id, vmRef)
		}
	}()

	// #4: Mimic the race condition by running the concurrent CreateSnapshot and DeleteSnapshot operations
	logger.Info("Step 4: Testing the API behavior under concurrent snapshot invocations")
	errChannels := make([]chan error, nIVDs)
	var wg sync.WaitGroup
	var mutex sync.Mutex
	for i := 0; i < nIVDs; i++ {
		wg.Add(1)
		go worker(&wg, &mutex, logger, params, i, ivdIds[i], ivdDs, errChannels)
	}
	wg.Wait()

	defer func() {
		logger.Debugf("Always clean up snapshots created in the test")
		for i := 0; i < nIVDs; i++ {
			logger.Debugf("Cleaning up snapshots for IVD %v", ivdIds[i].Id)
			snapshotInfos, err := ivdPETM.vslmManager.RetrieveSnapshotInfo(ctx, ivdIds[i])
			if err != nil {
				t.Fatalf("Failed at retrieving snapshot info from IVD %v with err: %v", ivdIds[i].Id, err)
			}

			if len(snapshotInfos) == 0 {
				logger.Debugf("No unexpected snasphot left behind for IVD %v", ivdIds[i].Id)
				continue
			}

			for _, snapshotInfo := range snapshotInfos {
				logger.Debugf("Cleaning up snapshot %v created for IVD %v but failed to be deleted", snapshotInfo.Id.Id, ivdIds[i].Id)
				ivdPE, err := ivdPETM.GetProtectedEntity(ctx, newProtectedEntityID(ivdIds[i]))
				if err != nil {
					t.Fatalf("[Cleanup] Failed to get IVD protected entity at the cleanup phase with err: %v", err)
				}
				peSnapID := astrolabe.NewProtectedEntitySnapshotID(snapshotInfo.Id.Id)
				_, err = ivdPE.DeleteSnapshot(ctx, peSnapID, make(map[string]map[string]interface{}))
				if err != nil {
					t.Fatalf("[Cleanup] Failed to DeleteSnapshot, %v, on IVD protected entity, %v with err: %v", peSnapID.GetID(), ivdPE.GetID().GetID(), err)
				}
			}
		}
	}()

	// Error Handling
	var result bool
	result = true
	for i := 0; i < nIVDs; i++ {
		err := <-errChannels[i]
		if err != nil {
			result = false
			t.Errorf("Worker %v on IVD %v failed with err: %v", i, ivdIds[i].Id, err)
		}
	}

	if !result {
		t.Fatal("Test Failed")
	}

}

func worker(wg *sync.WaitGroup, mutex *sync.Mutex, logger logrus.FieldLogger, params map[string]interface{}, id int, diskId types.ID, datastore types.ManagedObjectReference, errChans []chan error) {
	log := logger.WithFields(logrus.Fields{
		"WorkerID": id,
		"IvdID":    diskId.Id,
	})
	var err error
	log.Debugf("Worker starting")
	defer func() {
		log.Debugf("Worker completed with err: %v", err)
	}()

	errChans[id] = make(chan error)
	defer func() {
		errChans[id] <- err
		close(errChans[id])
	}()

	defer wg.Done()

	ctx := context.Background()

	s3Config := astrolabe.S3Config{
		URLBase: "VOID_URL",
	}
	ivdPETM, err := NewIVDProtectedEntityTypeManager(params, s3Config, logger)
	if err != nil {
		log.Error("Failed to get a new ivd PETM")
		return
	}

	ivdPE, err := ivdPETM.GetProtectedEntity(ctx, newProtectedEntityID(diskId))
	if err != nil {
		log.Error("Failed to get IVD protected entity")
		return
	}

	log.Debugf("Creating a snapshot on IVD protected entity")
	peSnapID, err := createSnapshotLocked(mutex, ctx, ivdPE, log)
	if err != nil {
		log.Error("Failed to snapshot the IVD protected entity")
		return
	}

	log.Debugf("Retrieving the newly created snapshot, %v, on IVD protected entity, %v", peSnapID.GetID(), ivdPE.GetID().GetID())
	_, err = ivdPETM.vslmManager.RetrieveSnapshotDetails(ctx, diskId, NewIDFromString(peSnapID.String()))
	if err != nil {
		if soap.IsSoapFault(err) {
			soapFault := soap.ToSoapFault(err)
			soapType := reflect.TypeOf(soapFault)
			log.WithError(err).Errorf("soap fault type: %v, err: %v", soapType, soapFault)
			faultMsg := soap.ToSoapFault(err).String
			if strings.Contains(faultMsg, "A specified parameter was not correct: snapshotId") {
				log.WithError(err).Error("Unexpected InvalidArgument soap fault due to race condition")
				return
			}
			log.WithError(err).Error("Unexpected soap fault")
		} else {
			log.WithError(err).Error("Unexpected other fault")
		}

		return
	}

	log.Debugf("Deleting the newly created snapshot, %v, on IVD protected entity, %v", peSnapID.GetID(), ivdPE.GetID().GetID())
	_, err = ivdPE.DeleteSnapshot(ctx, peSnapID, make(map[string]map[string]interface{}))
	if err != nil {
		log.WithError(err).Errorf("Failed to DeleteSnapshot, %v, on IVD protected entity, %v", peSnapID.GetID(), ivdPE.GetID().GetID())
	}
}

func createSnapshotLocked(mutex *sync.Mutex, ctx context.Context, ivdPE astrolabe.ProtectedEntity, log logrus.FieldLogger) (astrolabe.ProtectedEntitySnapshotID, error) {
	log.Debugf("Acquiring the lock on CreateSnapshot")
	mutex.Lock()
	log.Debugf("Acquired the lock on CreateSnapshot")
	defer func() {
		mutex.Unlock()
		log.Debugf("Released the lock on CreateSnapshot")
	}()
	peSnapID, err := ivdPE.Snapshot(ctx, nil)
	if err != nil {
		log.Error("Failed to snapshot the IVD protected entity")
		return astrolabe.ProtectedEntitySnapshotID{}, err
	}
	return peSnapID, nil
}

func getCreateSpec(name string, capacity int64, datastore types.ManagedObjectReference, profile []types.BaseVirtualMachineProfileSpec) types.VslmCreateSpec {
	keepAfterDeleteVm := true
	return types.VslmCreateSpec{
		Name:              name,
		KeepAfterDeleteVm: &keepAfterDeleteVm,
		BackingSpec: &types.VslmCreateSpecDiskFileBackingSpec{
			VslmCreateSpecBackingSpec: types.VslmCreateSpecBackingSpec{
				Datastore: datastore,
			},
		},
		CapacityInMB: capacity,
		Profile:      profile,
	}
}

func getRandomName(prefix string, nDigits int) string {
	rand.Seed(time.Now().UnixNano())
	num := rand.Int63n(int64(math.Pow10(nDigits)))
	numstr := strconv.FormatInt(num, 10)
	return fmt.Sprintf("%s-%s", prefix, numstr)
}

func getEncryptionProfileId(ctx context.Context, client *vim25.Client) (string, error) {
	pbmClient, err := pbm.NewClient(ctx, client)
	if err != nil {
		return "", err
	}

	encryptionProfileName := "VM Encryption Policy"
	return pbmClient.ProfileIDByName(ctx, encryptionProfileName)
}

func getProfileSpecs(profileId string) []types.BaseVirtualMachineProfileSpec {
	var profileSpecs []types.BaseVirtualMachineProfileSpec
	if profileId == "" {
		profileSpecs = append(profileSpecs, &types.VirtualMachineDefaultProfileSpec{})
	} else {
		profileSpecs = append(profileSpecs, &types.VirtualMachineDefinedProfileSpec{
			VirtualMachineProfileSpec: types.VirtualMachineProfileSpec{},
			ProfileId:                 profileId,
		})
	}
	return profileSpecs
}

func attachDiskAsync(ctx context.Context, client *vim25.Client, vm types.ManagedObjectReference, diskId types.ID, datastore types.ManagedObjectReference) (*object.Task, error) {
	req := types.AttachDisk_Task{
		This:       vm.Reference(),
		DiskId:     diskId,
		Datastore:  datastore.Reference(),
		UnitNumber: nil,
	}

	res, err := methods.AttachDisk_Task(ctx, client, &req)
	if err != nil {
		return nil, err
	}

	return object.NewTask(client, res.Returnval), nil
}

func attachDisk(ctx context.Context, client *vim25.Client, vmRef types.ManagedObjectReference, diskId types.ID, datastore types.ManagedObjectReference, logger logrus.FieldLogger) error {
	logger.Debugf("Attaching the disk %v to the VM %v", diskId.Id, vmRef)
	vimTask, err := attachDiskAsync(ctx, client, vmRef, diskId, datastore)
	if err != nil {
		return err
	}

	err = vimTask.Wait(ctx)
	if err != nil {
		return err
	}

	logger.Debugf("Disk %v is attached to the VM %v", diskId.Id, vmRef)
	return nil
}

func detachDiskAsync(ctx context.Context, client *vim25.Client, vm types.ManagedObjectReference, diskId types.ID) (*object.Task, error) {
	req := types.DetachDisk_Task{
		This:   vm.Reference(),
		DiskId: diskId,
	}

	res, err := methods.DetachDisk_Task(ctx, client, &req)
	if err != nil {
		return nil, err
	}

	return object.NewTask(client, res.Returnval), nil
}

func detachDisk(ctx context.Context, client *vim25.Client, vmRef types.ManagedObjectReference, diskId types.ID, logger logrus.FieldLogger) error {
	logger.Debugf("Detaching the disk %v from the VM %v", diskId.Id, vmRef)
	vimTask, err := detachDiskAsync(ctx, client, vmRef, diskId)
	if err != nil {
		return err
	}

	err = vimTask.Wait(ctx)
	if err != nil {
		return err
	}

	logger.Debugf("Disk %v is detached from the VM %v", diskId.Id, vmRef)
	return nil
}

func createDummyVm(ctx context.Context, client *vim25.Client, vmHost types.ManagedObjectReference, vmProfile []types.BaseVirtualMachineProfileSpec, logger logrus.FieldLogger) (*object.VirtualMachine, error) {
	logger.Debugf("Creating a dummy VM on host %v", vmHost)

	// pick an accessible datastore from the VM host for VM home directory.
	vmDs, err := pickOneAccessibleDatastoreFromHosts(ctx, client, []types.ManagedObjectReference{vmHost}, nil, logger)
	if err != nil {
		return nil, err
	}

	// retrieve the managed object of VM datastore from vCenter property collector
	pc := property.DefaultCollector(client)
	var vmDsMo mo.Datastore
	err = pc.RetrieveOne(ctx, vmDs.Reference(), []string{"name"}, &vmDsMo)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to get the managed object of datastore %v", vmDs)
		logger.Errorf(errorMsg)
		return nil, errors.Wrap(err, errorMsg)
	}

	logger.Debugf("Creating VM on host: %v, and datastore: %v(%v)", vmHost.Reference(), vmDsMo.Name, vmDs.Reference())
	vmName := getRandomName("vm", 6)

	// prepare for VM config spec
	virtualMachineConfigSpec := types.VirtualMachineConfigSpec{
		Name: vmName,
		Files: &types.VirtualMachineFileInfo{
			VmPathName: "[" + vmDsMo.Name + "]",
		},
		Annotation: "Quick Dummy",
		GuestId:    "otherLinux64Guest",
		NumCPUs:    1,
		MemoryMB:   128,
		DeviceChange: []types.BaseVirtualDeviceConfigSpec{
			&types.VirtualDeviceConfigSpec{
				Operation: types.VirtualDeviceConfigSpecOperationAdd,
				Device: &types.ParaVirtualSCSIController{
					VirtualSCSIController: types.VirtualSCSIController{
						SharedBus: types.VirtualSCSISharingNoSharing,
						VirtualController: types.VirtualController{
							BusNumber: 0,
							VirtualDevice: types.VirtualDevice{
								Key: 1000,
							},
						},
					},
				},
			},
		},
		VmProfile: vmProfile,
	}

	finder := find.NewFinder(client)
	defaultFolder, err := finder.DefaultFolder(ctx)
	defaultResourcePool, err := finder.DefaultResourcePool(ctx)
	vmHostSystem := object.NewHostSystem(client, vmHost)
	task, err := defaultFolder.CreateVM(ctx, virtualMachineConfigSpec, defaultResourcePool, vmHostSystem)
	if err != nil {
		logger.Errorf("Failed to create VM. Error: %v", err)
		return nil, err
	}

	vmTaskInfo, err := task.WaitForResult(ctx, nil)
	if err != nil {
		logger.Errorf("Error occurred while waiting for create VM task result. Error: %v", err)
		return nil, err
	}

	vmRef := vmTaskInfo.Result.(object.Reference)
	vmMo := object.NewVirtualMachine(client, vmRef.Reference())

	logger.Debugf("VM %v(%v) is created on host %v and datastore %v(%v)", vmName, vmMo.Reference(), vmHost, vmDsMo.Name, vmDs.Reference())
	return vmMo, nil
}


func deleteVm(ctx context.Context, client *vim25.Client, vmRef types.ManagedObjectReference, logger logrus.FieldLogger) error {
	vmMo := object.NewVirtualMachine(client, vmRef)

	var err error
	var vmName string
	if vmName, err = vmMo.ObjectName(ctx); err != nil {
		return errors.Wrapf(err, "deleteVm: Failed to get VM name from VM reference %v", vmRef)
	}
	logger.Debugf("Deleting the VM %v(%v)", vmName, vmRef)

	vimTask, err := vmMo.Destroy(ctx)
	if err != nil {
		return errors.Wrapf(err, "Failed to destroy the VM %v(%v)", vmName, vmRef)
	}
	err = vimTask.Wait(ctx)
	if err != nil {
		return errors.Wrapf(err,"Failed at waiting for the destroy of VM %v(%v)", vmName, vmRef)
	}

	logger.Debugf("VM %v(%v) is deleted", vmName, vmRef)
	return nil
}

func powerOnVm(ctx context.Context, client *vim25.Client, vmRef types.ManagedObjectReference, logger logrus.FieldLogger) error {
	vmMo := object.NewVirtualMachine(client, vmRef)

	var err error
	var vmName string
	if vmName, err = vmMo.ObjectName(ctx); err != nil {
		return errors.Wrapf(err, "powerOnVm: Failed to get VM name from VM reference %v", vmRef)
	}
	logger.Debugf("Powering on the VM %v(%v)", vmName, vmRef)

	vimTask, err := vmMo.PowerOn(ctx)
	if err != nil {
		return errors.Wrapf(err, "Failed to create a PowerOn task for VM %v(%v)", vmName, vmRef)
	}
	err = vimTask.Wait(ctx)
	if err != nil {
		return errors.Wrapf(err, "Failed at waiting for the PowerOn task for VM %v(%v)", vmName, vmRef)
	}

	logger.Debugf("VM %v(%v) is powered on", vmName, vmRef)
	return nil
}

func powerOffVm(ctx context.Context, client *vim25.Client, vmRef types.ManagedObjectReference, logger logrus.FieldLogger) error {
	vmMo := object.NewVirtualMachine(client, vmRef)

	var err error
	var vmName string
	if vmName, err = vmMo.ObjectName(ctx); err != nil {
		return errors.Wrapf(err, "Failed to get VM name from VM reference %v", vmRef)
	}
	logger.Debugf("Powering off the VM %v(%v)", vmName, vmRef)

	vimTask, err := vmMo.PowerOff(ctx)
	if err != nil {
		return errors.Wrapf(err, "Failed to create a PowerOff task for VM %v(%v)", vmName, vmRef)
	}
	err = vimTask.Wait(ctx)
	if err != nil {
		return errors.Wrapf(err, "Failed at waiting for the PowerOff task for VM %v(%v)", vmName, vmRef)
	}

	logger.Debugf("VM %v(%v) is powered off", vmName, vmRef)
	return nil
}

func createDisk(ctx context.Context, ivdPETM *IVDProtectedEntityTypeManager, createSpec types.VslmCreateSpec, logger logrus.FieldLogger) (types.ID, error){
	logger.Debugf("Creating an IVD disk with spec: %v", pretty.Sprint(createSpec))
	vslmTask, err := ivdPETM.vslmManager.CreateDisk(ctx, createSpec)
	if err != nil {
		return types.ID{}, errors.Wrap(err, "Failed to create task for CreateDisk invocation")
	}

	taskResult, err := vslmTask.Wait(ctx, waitTime)
	if err != nil {
		return types.ID{}, errors.Wrap(err,"Failed at waiting for the CreateDisk invocation")
	}
	vStorageObject := taskResult.(types.VStorageObject)
	diskID := vStorageObject.Config.Id
	logger.Debugf("IVD disk, %v, is created", diskID.Id)
	return diskID, nil
}

func deleteDisk(ctx context.Context, ivdPETM *IVDProtectedEntityTypeManager, id types.ID, logger logrus.FieldLogger) error {
	logger.Debugf("Deleting the IVD disk %v", id.Id)
	vslmTask, err := ivdPETM.vslmManager.Delete(ctx, id)
	if err != nil {
		return errors.Wrap(err, "Failed to create task for DeleteDisk invocation")
	}

	_, err = vslmTask.Wait(ctx, waitTime)
	if err != nil {
		return errors.Wrap(err,"Failed at waiting for the DeleteDisk invocation")
	}

	logger.Debugf("IVD, %v, is deleted", id.Id)
	return nil
}

func getIVDConfigParams(vcUrl *url.URL) map[string]interface{} {
	params := make(map[string]interface{})
	params[vsphere.HostVcParamKey] = vcUrl.Host
	if vcUrl.Port() == "" {
		params[vsphere.PortVcParamKey] = "443"
	} else {
		params[vsphere.PortVcParamKey] = vcUrl.Port()
	}
	params[vsphere.UserVcParamKey] = vcUrl.User.Username()
	password, _ := vcUrl.User.Password()
	params[vsphere.PasswordVcParamKey] = password
	params[vsphere.InsecureFlagVcParamKey] = "true"
	params[vsphere.ClusterVcParamKey] = ""

	return params
}

func TestBackupEncryptedIVD(t *testing.T) {
	// #0: Setup the environment
	// Prerequisite: export ASTROLABE_VC_URL='https://<VC USER>:<VC USER PASSWORD>@<VC IP>/sdk'
	u, exist := os.LookupEnv("ASTROLABE_VC_URL")
	if !exist {
		t.Skipf("ASTROLABE_VC_URL is not set")
	}

	enableDebugLog := false
	enableDebugLogStr, ok := os.LookupEnv("ENABLE_DEBUG_LOG")
	if ok {
		if res, _ := strconv.ParseBool(enableDebugLogStr); res {
			enableDebugLog = true
		}
	}

	vcUrl, err := soap.ParseURL(u)
	if err != nil {
		t.Skipf("Failed to parse the env variable, ASTROLABE_VC_URL, with err: %v", err)
	}

	ctx := context.Background()
	logger := logrus.New()
	formatter := new(logrus.TextFormatter)
	formatter.TimestampFormat = time.RFC3339Nano
	formatter.FullTimestamp = true
	logger.SetFormatter(formatter)
	if enableDebugLog {
		logger.SetLevel(logrus.DebugLevel)
	}

	// BEGIN: configuration options
	// Use two IVDs in this test case if not explicitly specified
	nIVDs := 2
	nIVDsStr, ok := os.LookupEnv("NUM_OF_IVD")
	if ok {
		nIVDsInt, err := strconv.Atoi(nIVDsStr)
		if err == nil && nIVDsInt > 0 && nIVDsInt <= MaxNumOfIVDs {
			nIVDs = nIVDsInt
		}
	}

	// Use Encryption
	useEncryptedIVD := false
	useEncryptionStr, ok := os.LookupEnv("USE_ENCRYPTED_IVD")
	if ok {
		if res, _ := strconv.ParseBool(useEncryptionStr); res {
			useEncryptedIVD = true
		}
	}
	logger.Debugf("Configuration options: numOfIVDs = %v, useEncryption=%v", nIVDs, useEncryptedIVD)
	// END: configuration options

	ivdPETM, err := NewIVDProtectedEntityTypeManager(getIVDConfigParams(vcUrl), astrolabe.S3Config{URLBase: "VOID_URL"}, logger)
	if err != nil {
		t.Skipf("Failed to get a new ivd PETM: %v", err)
	}

	if err := BackupIVDsUtil(t, ctx, ivdPETM, nIVDs, useEncryptedIVD, logger); err != nil {
		t.Fatal(err)
	}
}

func BackupIVDsUtil(t *testing.T, ctx context.Context, ivdPETM *IVDProtectedEntityTypeManager, nIVDs int, useEncryptedIVD bool, logger logrus.FieldLogger) error {
	var err error
	virtualCenter := ivdPETM.vcenter

	var encryptionProfileId string
	if useEncryptedIVD {
		encryptionProfileId, err = getEncryptionProfileId(ctx, virtualCenter.Client.Client)
		if err != nil {
			t.Skipf("Failed to get encryption profile ID: %v", err)
		}
	}

	// pick a host for VM creation
	vmHost, err := pickOneHost(ctx, virtualCenter.Client.Client, logger)
	if err != nil {
		t.Skipf("Failed to find a host for VM creation with err: %v", err)
	}

	// #1: Create an encrypted VM
	logger.Info("Step 1: Creating a VM")
	vmProfile := getProfileSpecs(encryptionProfileId)
	vmMo, err := createDummyVm(ctx, virtualCenter.Client.Client, vmHost, vmProfile, logger)
	if err != nil {
		t.Skipf("Failed to create a VM with err: %v", err)
	}
	vmRef := vmMo.Reference()
	defer func() {
		if err := deleteVm(ctx, virtualCenter.Client.Client, vmRef, nil); err != nil {
			t.Skipf("Failed to delete VM %v with err: %v", vmRef, err)
		}
	}()

	// #2: Poweron the VM
	logger.Info("Step 2: Powering on a VM")
	if err := powerOnVm(ctx, virtualCenter.Client.Client, vmRef, nil); err != nil {
		t.Skipf("Failed to power on the VM %v with err: %v", vmRef, err)
	}
	//logger.Debugf("VM, %v(%v), powered on", vmRef, vmName)
	defer func() {
		if err := powerOffVm(ctx, virtualCenter.Client.Client, vmRef, nil); err != nil {
			t.Skipf("Failed to power off the VM %v with err: %v", vmRef, err)
		}
		//logger.Debugf("VM, %v(%v), powered off", vmRef, vmName)
	}()

	// #3: Create encrypted IVDs

	logger.Infof("Creating %v encrypted IVDs", nIVDs)
	ivdProfile := vmProfile
	ivdDs, err := pickOneAccessibleDatastoreFromHosts(ctx, virtualCenter.Client.Client, []types.ManagedObjectReference{vmHost}, nil, logger)
	if err != nil {
		t.Skipf("Failed to find an accessible datastore from VM host %v with err: %v", vmHost, err)
	}

	var ivdIds []types.ID
	for i := 0; i < nIVDs; i++ {
		createSpec := getCreateSpec(getRandomName("ivd", 6), 50, ivdDs, ivdProfile)
		diskID, err := createDisk(ctx, ivdPETM, createSpec, logger)
		if err != nil {
			t.Skipf("Failed to create IVD with err: %v", err)
		}
		ivdIds = append(ivdIds, diskID)
	}

	if ivdIds == nil {
		t.Skipf("Failed to create a list of ivds as expected")
	}

	defer func() {
		for i := 0; i < nIVDs; i++ {
			if err := deleteDisk(ctx, ivdPETM, ivdIds[i], logger); err != nil {
				t.Skipf("Failed to delete IVD %v with err: %v", ivdIds[i].Id, err)
			}
		}
	}()

	// #4: Attach it to VM
	logger.Infof("Step 4: Attaching IVDs to VM %v", vmRef)
	for i := 0; i < nIVDs; i++ {
		err = attachDisk(ctx, virtualCenter.Client.Client, vmRef.Reference(), ivdIds[i], ivdDs.Reference(), nil)
		if err != nil {
			t.Skipf("Failed to attach ivd, %v, to, VM, %v with err: %v", ivdIds[i].Id, vmRef, err)
		}

		logger.Debugf("IVD, %v, attached to VM, %v", ivdIds[i].Id, vmRef)
	}

	defer func() {
		for i := 0; i < nIVDs; i++ {
			err = detachDisk(ctx, virtualCenter.Client.Client, vmRef.Reference(), ivdIds[i], nil)
			if err != nil {
				t.Skipf("Failed to detach ivd, %v, to, VM, %v with err: %v", ivdIds[i].Id, vmRef, err)
			}

			logger.Debugf("IVD, %v, detached from VM, %v", ivdIds[i].Id, vmRef)
		}
	}()
	// #5: Backup the IVD
	logger.Infof("Step 5: Backing up encrypted IVDs")
	// #5.1: Create an IVD snapshot
	logger.Debugf("Creating a snapshot on each IVD")
	//var snapPEIDs []astrolabe.ProtectedEntityID
	snapPEIDtoIvdPEMap := make(map[astrolabe.ProtectedEntityID]astrolabe.ProtectedEntity)
	for _, ivdId := range ivdIds {
		ivdPE, err := ivdPETM.GetProtectedEntity(ctx, newProtectedEntityID(ivdId))
		if err != nil {
			t.Skipf("Failed to get IVD protected entity for the IVD, %v", ivdId)
		}

		snapID, err := ivdPE.Snapshot(ctx, nil)
		if err != nil {
			t.Errorf("Failed to snapshot the IVD protected entity, %v", ivdId)
		}
		snapPEID := astrolabe.NewProtectedEntityIDWithSnapshotID("ivd", ivdId.Id, snapID)
		snapPEIDtoIvdPEMap[snapPEID] = ivdPE
	}

	// #5.2: Copy the IVD snapshot to specified object store
	logger.Debugf("Copying the IVD snapshots to object store")
	s3PETM, err := setupPETM("ivd", logger)
	if err != nil {
		t.Skipf("Failed to setup s3 PETM for the object store")
	}

	snapPEIDtos3PEMap := make(map[astrolabe.ProtectedEntityID]astrolabe.ProtectedEntity)
	for snapPEID, _ := range snapPEIDtoIvdPEMap {
		snapPE, err := ivdPETM.GetProtectedEntity(ctx, snapPEID)
		if err != nil {
			t.Fatalf("Failed to get snapshot protected entity for the IVD snapshot, %v", snapPEID.String())
		}
		s3PE, err := s3PETM.Copy(ctx, snapPE, make(map[string]map[string]interface{}), astrolabe.AllocateNewObject)
		if err != nil {
			t.Fatalf("Failed to copy snapshot PE, %v, to S3 object store: %v", snapPEID.String(), err)
		}
		snapPEIDtos3PEMap[snapPEID] = s3PE
	}

	defer func() {
		for snapPEID, _ := range snapPEIDtoIvdPEMap {
			s3PE := snapPEIDtos3PEMap[snapPEID]
			_, err := s3PE.DeleteSnapshot(ctx, snapPEID.GetSnapshotID(), make(map[string]map[string]interface{}))
			if err != nil {
				logger.Errorf("Failed to delete snapshot, %v, on object store: %v", snapPEID.GetSnapshotID().String(), err)
			}
		}
	}()

	// #5.3: Delete the local IVD snapshot
	for snapPEID, ivdPE := range snapPEIDtoIvdPEMap {
		_, err := ivdPE.DeleteSnapshot(ctx, snapPEID.GetSnapshotID(), make(map[string]map[string]interface{}))
		if err != nil {
			t.Fatalf("Failed to delete local IVD snapshot, %v: %v", snapPEID.GetSnapshotID(), err)
		}
	}
	return err
}


func setupPETM(typeName string, logger logrus.FieldLogger) (*s3repository.ProtectedEntityTypeManager, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-west-1")},
	)
	if err != nil {
		return nil, err
	}
	s3petm, err := s3repository.NewS3RepositoryProtectedEntityTypeManager(typeName, *sess, "velero-plugin-s3-repo",
		"plugins/vsphere-volumes-repo/", logger)
	if err != nil {
		return nil, err
	}
	return s3petm, err
}
