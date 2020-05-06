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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/sirupsen/logrus"
	"github.com/vmware-tanzu/astrolabe/pkg/astrolabe"
	"github.com/vmware-tanzu/astrolabe/pkg/s3repository"
	"github.com/vmware/govmomi/cns"
	cnstypes "github.com/vmware/govmomi/cns/types"
	vim25types "github.com/vmware/govmomi/vim25/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestProtectedEntityTypeManager(t *testing.T) {
	var vcUrl url.URL
	vcUrl.Scheme = "https"
	vcUrl.Host = "10.160.127.39"
	vcUrl.User = url.UserPassword("administrator@vsphere.local", "Admin!23")
	vcUrl.Path = "/sdk"

	t.Logf("%s\n", vcUrl.String())

	ivdPETM, err := NewIVDProtectedEntityTypeManagerFromURL(&vcUrl, "/ivd", true, logrus.New())
	ctx := context.Background()

	pes, err := ivdPETM.GetProtectedEntities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("# of PEs returned = %d\n", len(pes))
}

func verifyMdIsRestoredAsExpected(md metadata, version string, logger logrus.FieldLogger) bool {
	var reservedLabels []string
	if strings.Contains(version, "6.7U3") {
		reservedLabels = []string {
			"cns.clusterID",
			"cns.clusterType",
			"cns.vSphereUser",
			"cns.k8s.pvName",
			"cns.tag",
		}
	} else if strings.HasPrefix(version, "7.0") {
		reservedLabels = []string {
			"cns.containerCluster.clusterFlavor",
			"cns.containerCluster.clusterId",
			"cns.containerCluster.clusterType",
			"cns.containerCluster.vSphereUser",
			"cns.k8s.pv.name",
			"cns.tag",
			"cns.version",
		}
	} else {
		logger.Debug("Newer VC version than what we expect. Skip the verification.")
		return true
	}

	extendedMdMap := make(map[string]string)

	for _, label := range md.ExtendedMetadata {
		extendedMdMap[label.Key] = label.Value
	}

	for _, key := range reservedLabels {
		_, ok := extendedMdMap[key]
		if !ok {
			return false
		}
	}

	return true
}

func TestCreateCnsVolume(t *testing.T) {
	path := os.Getenv("KUBECONFIG")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// path/to/whatever does not exist
		t.Skipf("The KubeConfig file, %v, is not exist", path)
	}

	config, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		t.Fatalf("Failed to build k8s config from kubeconfig file: %+v ", err)
	}

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	ctx := context.Background()

	// Step 1: To create the IVD PETM, get all PEs and select one as the reference.
	vcUrl, insecure, err := GetVcUrlFromConfig(config, logger)
	if err != nil {
		t.Fatalf("Failed to get VC config from params: %+v", err)
	}

	ivdPETM, err := NewIVDProtectedEntityTypeManagerFromURL(vcUrl, "/ivd", insecure, logger)
	if err != nil {
		t.Fatalf("Failed to get a new ivd PETM: %+v", err)
	}
	version := ivdPETM.client.Version
	logger.Debugf("vcUrl = %v, version = %v", vcUrl, version)

	var queryFilter cnstypes.CnsQueryFilter
	var volumeIDList []cnstypes.CnsVolumeId

	// construct a dummy metadata object
	md := metadata{
		vim25types.VStorageObject{
			DynamicData: vim25types.DynamicData{},
			Config:      vim25types.VStorageObjectConfigInfo{
				BaseConfigInfo:  vim25types.BaseConfigInfo{
					DynamicData:                 vim25types.DynamicData{},
					Id:                          vim25types.ID{},
					Name:                        "xyz",
					CreateTime:                  time.Time{},
					KeepAfterDeleteVm:           nil,
					RelocationDisabled:          nil,
					NativeSnapshotSupported:     nil,
					ChangedBlockTrackingEnabled: nil,
					Backing:                     nil,
					Iofilter:                    nil,
				},
				CapacityInMB:    10,
				ConsumptionType: nil,
				ConsumerId:      nil,
			},
		},
		vim25types.ManagedObjectReference{},
		nil,
	}

	logger.Debugf("IVD md: %v", md.ExtendedMetadata)

	t.Logf("PE name, %v", md.VirtualStorageObject.Config.Name)
	md = FilterLabelsFromMetadataForCnsAPIs(md, "cns", logger)
	volumeId, err := createCnsVolumeWithClusterConfig(ctx, config, ivdPETM.client, ivdPETM.cnsClient, md, logger)
	if err != nil {
		t.Fatal("Fail to provision a new volume")
	}

	t.Logf("CNS volume, %v, created", volumeId)
	var volumeIDListToDelete []cnstypes.CnsVolumeId
	volumeIDList = append(volumeIDListToDelete, cnstypes.CnsVolumeId{Id: volumeId})

	defer func () {
		// Always delete the newly created volume at the end of test
		t.Logf("Deleting volume: %+v", volumeIDList)
		deleteTask, err := ivdPETM.cnsClient.DeleteVolume(ctx, volumeIDList, true)
		if err != nil {
			t.Errorf("Failed to delete volume. Error: %+v \n", err)
			t.Fatal(err)
		}
		deleteTaskInfo, err := cns.GetTaskInfo(ctx, deleteTask)
		if err != nil {
			t.Errorf("Failed to delete volume. Error: %+v \n", err)
			t.Fatal(err)
		}
		deleteTaskResult, err := cns.GetTaskResult(ctx, deleteTaskInfo)
		if err != nil {
			t.Errorf("Failed to detach volume. Error: %+v \n", err)
			t.Fatal(err)
		}
		if deleteTaskResult == nil {
			t.Fatalf("Empty delete task results")
		}
		deleteVolumeOperationRes := deleteTaskResult.GetCnsVolumeOperationResult()
		if deleteVolumeOperationRes.Fault != nil {
			t.Fatalf("Failed to delete volume: fault=%+v", deleteVolumeOperationRes.Fault)
		}
		t.Logf("Volume deleted sucessfully")
	} ()

	// Step 4: Query the volume result for the newly created protected entity/volume
	queryFilter.VolumeIds = volumeIDList
	queryResult, err := ivdPETM.cnsClient.QueryVolume(ctx, queryFilter)
	if err != nil {
		t.Errorf("Failed to query volume. Error: %+v \n", err)
		t.Fatal(err)
	}
	logger.Debugf("Sucessfully Queried Volumes. queryResult: %+v", queryResult)

	newPE, err := newIVDProtectedEntity(ivdPETM, newProtectedEntityID(NewIDFromString(volumeId)))
	if err != nil {
		t.Fatalf("Failed to get a new PE: %v", err)
	}

	newMD, err := newPE.getMetadata(ctx)
	if err != nil {
		t.Fatalf("Failed to get the metadata: %v", err)
	}

	logger.Debugf("IVD md: %v", newMD.ExtendedMetadata)

	// Verify the test result between the actual and expected
	if md.VirtualStorageObject.Config.Name != queryResult.Volumes[0].Name {
		t.Errorf("Volume names mismatch, src: %v, dst: %v", md.VirtualStorageObject.Config.Name, queryResult.Volumes[0].Name)
	} else {
		t.Logf("Volume names match, name: %v", md.VirtualStorageObject.Config.Name)
	}
}


func TestRestoreCnsVolumeFromSnapshot(t *testing.T) {
	path := os.Getenv("KUBECONFIG")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// path/to/whatever does not exist
		t.Skipf("The KubeConfig file, %v, is not exist", path)
	}

	config, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		t.Fatalf("Failed to build k8s config from kubeconfig file: %+v ", err)
	}

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	ctx := context.Background()

	// Step 1: To create the IVD PETM, get all PEs and select one as the reference.
	vcUrl, insecure, err := GetVcUrlFromConfig(config, logger)
	if err != nil {
		t.Fatalf("Failed to get VC config from params: %+v", err)
	}

	ivdPETM, err := NewIVDProtectedEntityTypeManagerFromURL(vcUrl, "/ivd", insecure, logger)
	if err != nil {
		t.Fatalf("Failed to get a new ivd PETM: %+v", err)
	}
	version := ivdPETM.client.Version
	logger.Debugf("vcUrl = %v, version = %v", vcUrl, version)

	peIDs, err := ivdPETM.GetProtectedEntities(ctx)
	if err != nil {
		t.Fatalf("Failed to get all PEs: %+v", err)
	}
	t.Logf("# of PEs returned = %d\n", len(peIDs))

	var md metadata
	var queryFilter cnstypes.CnsQueryFilter
	var volumeIDList []cnstypes.CnsVolumeId

	peID := peIDs[0]
	t.Logf("Selected PE ID: %v", peID.String())

	// Get general govmomi client and cns client
	// Step 2: Query the volume result for the selected protected entity/volume
	volumeIDList = append(volumeIDList, cnstypes.CnsVolumeId{Id: peID.GetID()})

	queryFilter.VolumeIds = volumeIDList
	queryResult, err := ivdPETM.cnsClient.QueryVolume(ctx, queryFilter)
	if err != nil {
		t.Errorf("Failed to query volume. Error: %+v \n", err)
		t.Fatal(err)
	}
	logger.Debugf("Sucessfully Queried Volumes. queryResult: %+v", queryResult)

	// Step 3: Create a new volume with the same metadata as the selected one
	pe, err := newIVDProtectedEntity(ivdPETM, peID)
	if err != nil {
		t.Fatalf("Failed to get a new PE from the peID, %v: %v", peID.String(), err)
	}

	md, err = pe.getMetadata(ctx)
	if err != nil {
		t.Fatalf("Failed to get the metadata of the PE, %v: %v", pe.id.String(), err)
	}


	logger.Debugf("IVD md: %v", md.ExtendedMetadata)

	t.Logf("PE name, %v", md.VirtualStorageObject.Config.Name)
	md = FilterLabelsFromMetadataForCnsAPIs(md, "cns", logger)
	volumeId, err := createCnsVolumeWithClusterConfig(ctx, config, ivdPETM.client, ivdPETM.cnsClient, md, logger)
	if err != nil {
		t.Fatal("Fail to provision a new volume")
	}

	t.Logf("CNS volume, %v, created", volumeId)
	var volumeIDListToDelete []cnstypes.CnsVolumeId
	volumeIDList = append(volumeIDListToDelete, cnstypes.CnsVolumeId{Id: volumeId})

	defer func () {
		// Always delete the newly created volume at the end of test
		t.Logf("Deleting volume: %+v", volumeIDList)
		deleteTask, err := ivdPETM.cnsClient.DeleteVolume(ctx, volumeIDList, true)
		if err != nil {
			t.Errorf("Failed to delete volume. Error: %+v \n", err)
			t.Fatal(err)
		}
		deleteTaskInfo, err := cns.GetTaskInfo(ctx, deleteTask)
		if err != nil {
			t.Errorf("Failed to delete volume. Error: %+v \n", err)
			t.Fatal(err)
		}
		deleteTaskResult, err := cns.GetTaskResult(ctx, deleteTaskInfo)
		if err != nil {
			t.Errorf("Failed to detach volume. Error: %+v \n", err)
			t.Fatal(err)
		}
		if deleteTaskResult == nil {
			t.Fatalf("Empty delete task results")
		}
		deleteVolumeOperationRes := deleteTaskResult.GetCnsVolumeOperationResult()
		if deleteVolumeOperationRes.Fault != nil {
			t.Fatalf("Failed to delete volume: fault=%+v", deleteVolumeOperationRes.Fault)
		}
		t.Logf("Volume deleted sucessfully")
	} ()

	// Step 4: Query the volume result for the newly created protected entity/volume
	queryFilter.VolumeIds = volumeIDList
	queryResult, err = ivdPETM.cnsClient.QueryVolume(ctx, queryFilter)
	if err != nil {
		t.Errorf("Failed to query volume. Error: %+v \n", err)
		t.Fatal(err)
	}
	logger.Debugf("Sucessfully Queried Volumes. queryResult: %+v", queryResult)

	newPE, err := newIVDProtectedEntity(ivdPETM, newProtectedEntityID(NewIDFromString(volumeId)))
	if err != nil {
		t.Fatalf("Failed to get a new PE from the peID, %v: %v", peID.String(), err)
	}

	newMD, err := newPE.getMetadata(ctx)
	if err != nil {
		t.Fatalf("Failed to get the metadata of the PE, %v: %v", pe.id.String(), err)
	}

	logger.Debugf("IVD md: %v", newMD.ExtendedMetadata)

	// Verify the test result between the actual and expected
	if md.VirtualStorageObject.Config.Name != queryResult.Volumes[0].Name {
		t.Errorf("Volume names mismatch, src: %v, dst: %v", md.VirtualStorageObject.Config.Name, queryResult.Volumes[0].Name)
	} else {
		t.Logf("Volume names match, name: %v", md.VirtualStorageObject.Config.Name)
	}

	if verifyMdIsRestoredAsExpected(newMD, version, logger) {
		t.Logf("Volume metadata is restored as expected")
	} else {
		t.Errorf("Volume metadata is NOT restored as expected")
	}
}

func TestDeleteSnapshotOnPodVm(t *testing.T) {
	path := os.Getenv("KUBECONFIG")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// path/to/whatever does not exist
		t.Skipf("The KubeConfig file, %v, is not exist", path)
	}

	config, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		t.Skipf("Failed to build k8s config from kubeconfig file: %+v ", err)
	}

	logger := logrus.New()
	formatter := new(logrus.TextFormatter)
	formatter.TimestampFormat = time.RFC3339Nano
	formatter.FullTimestamp = true
	logger.SetFormatter(formatter)
	//logger.SetLevel(logrus.InfoLevel)
	logger.SetLevel(logrus.DebugLevel)


	// Get PV using k8s API
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Skipf("Failed to get k8s clientSet from the given config: %v", config)
	}

	ns := "demo"
	// check if the demo namespace exists
	_, err = clientSet.CoreV1().Namespaces().Get(ns, metav1.GetOptions{})
	if err != nil {
		t.Skipf("The expected app namespace, %v, is not available", ns)
	}

	// list all PVCs in the demo namespace
	pvcList, err := clientSet.CoreV1().PersistentVolumeClaims(ns).List(metav1.ListOptions{})
	if err != nil || len(pvcList.Items) == 0 {
		t.Skipf("There is no PVC available in the expected app namespace, %v", ns)
	}

	// pick the PV bound to the very first PVC and extract its volume ID
	pvVolumeName := pvcList.Items[0].Spec.VolumeName
	pv, err := clientSet.CoreV1().PersistentVolumes().Get(pvVolumeName, metav1.GetOptions{})
	if err != nil {
		t.Skipf("Failed to find a PV attached to the app pod")
	}

	if pv.Spec.CSI == nil {
		t.Skipf("Skip non-CSI backed PV")
	}

	volumeId := pv.Spec.CSI.VolumeHandle
	logger.Debugf("volumeId = %v", volumeId)

	// create an IVD PETM
	ctx := context.Background()
	vcUrl, insecure, err := GetVcUrlFromConfig(config, logger)
	if err != nil {
		t.Skipf("Failed to get VC config from params: %+v", err)
	}

	ivdPETM, err := NewIVDProtectedEntityTypeManagerFromURL(vcUrl, "/ivd", insecure, logger)
	if err != nil {
		t.Skipf("Failed to get a new ivd PETM: %+v", err)
	}
	version := ivdPETM.client.Version

	logger.Debugf("vcUrl = %v, version = %v", vcUrl, version)

	ivdPE, err:= newIVDProtectedEntity(ivdPETM, newProtectedEntityID(NewIDFromString(volumeId)))
	if err != nil {
		t.Skipf("Failed to create ivd protected entity from volume, %v", volumeId)
	}

	// Create an IVD snapshot
	peSnapshotId, err := ivdPE.Snapshot(ctx)
	if err != nil {
		t.Skipf("Failed to create snapshot on IVD protected entity, %v", ivdPE.id.String())
	}

	// Delete the snapshot just created
	_, err = ivdPE.DeleteSnapshot(ctx, peSnapshotId)
	if err != nil {
		t.Fatalf("Failed to delete snapshot, %v, from IVD protected entity, %v", peSnapshotId.String(), ivdPE.id.String())
	}
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

func TestCopyIVDProtectedEntity(t *testing.T) {
	path := os.Getenv("KUBECONFIG")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// path/to/whatever does not exist
		t.Skipf("The KubeConfig file, %v, is not exist", path)
	}

	config, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		t.Skipf("Failed to build k8s config from kubeconfig file: %+v ", err)
	}

	// Get PV using k8s API
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Skipf("Failed to get k8s clientSet from the given config: %v", config)
	}

	logger := logrus.New()
	formatter := new(logrus.TextFormatter)
	formatter.TimestampFormat = time.RFC3339Nano
	formatter.FullTimestamp = true
	logger.SetFormatter(formatter)
	//logger.SetLevel(logrus.InfoLevel)
	logger.SetLevel(logrus.DebugLevel)

	ctx := context.Background()
	vcUrl, insecure, err := GetVcUrlFromConfig(config, logger)
	if err != nil {
		t.Skipf("Failed to get VC config from params: %v", err)
	}
	logger.Debugf("vcUrl = %v", vcUrl)
	ivdPETM, err := NewIVDProtectedEntityTypeManagerFromURL(vcUrl, "/ivd", insecure, logger)
	if err != nil {
		t.Skipf("Failed to get a new ivd PETM: %v", err)
	}

	s3PETM, err := setupPETM("ivd", logger)
	if err != nil {
		t.Skipf("Failed to get a new s3 PETM: %v", err)
	}

	// find a PV for backup&restore from the app namespace
	ns := "demo-app"
	// check if the demo namespace exists
	_, err = clientSet.CoreV1().Namespaces().Get(ns, metav1.GetOptions{})
	if err != nil {
		t.Skipf("The expected app namespace, %v, is not available", ns)
	}

	// list all PVCs in the demo namespace
	pvcList, err := clientSet.CoreV1().PersistentVolumeClaims(ns).List(metav1.ListOptions{})
	if err != nil || len(pvcList.Items) == 0 {
		t.Skipf("There is no PVC available in the expected app namespace, %v", ns)
	}

	// pick the PV bound to the very first PVC and extract its volume ID
	pvVolumeName := pvcList.Items[0].Spec.VolumeName
	pv, err := clientSet.CoreV1().PersistentVolumes().Get(pvVolumeName, metav1.GetOptions{})
	if err != nil {
		t.Skipf("Failed to find a PV attached to the app pod")
	}

	if pv.Spec.CSI == nil {
		t.Skipf("Skip non-CSI backed PV")
	}

	volumeId := pv.Spec.CSI.VolumeHandle
	logger.Debugf("volumeId = %v", volumeId)

	ivdPEID := astrolabe.NewProtectedEntityID("ivd", volumeId)
	var snapID astrolabe.ProtectedEntitySnapshotID

	ivdPE, err := ivdPETM.GetProtectedEntity(ctx, ivdPEID)
	if err != nil {
		t.Skipf("Failed to get an ivd PE, %v: %v", ivdPE.GetID().String(), err)
	}

	snapID, err = ivdPE.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Failed to create a snapshot on ivd PE, %v: %v", ivdPE.GetID().String(), err)
	}
	snapPEID := astrolabe.NewProtectedEntityIDWithSnapshotID("ivd", ivdPEID.GetID(), snapID)
	snapPE, err := ivdPETM.GetProtectedEntity(ctx, snapPEID)
	if err != nil {
		t.Fatalf("Failed to get an ivd snapshot PE, %v: %v", snapPE.GetID().String(), err)
	}

	defer func() {
		_, err := ivdPE.DeleteSnapshot(ctx, snapID)
		if err != nil {
			logger.Errorf("Failed to delete the local snapshot PE, %v: %v", snapPE.GetID().String(), err)
		} else {
			logger.Debugf("Local snapshot PE, %v, was cleaned up", snapPE.GetID().String())
		}

	}()

	s3PE, err := s3PETM.Copy(ctx, snapPE, astrolabe.AllocateNewObject)
	if err != nil {
		t.Fatalf("Failed to copy the snapshot PE, %v, to S3: %v", snapPE.GetID().String(), err)
	}
	logger.Infof("Backed up the snapshot PE, %v", s3PE.GetID().String())

	defer func() {
		_, err := s3PE.DeleteSnapshot(ctx, s3PE.GetID().GetSnapshotID())
		if err != nil {
			logger.Errorf("Failed to delete the local snapshot PE, %v: %v", snapPE.GetID().String(), err)
		} else {
			logger.Debugf("Remote snapshot PE, %v, was cleaned up", s3PE.GetID().String())
		}
	}()
}
