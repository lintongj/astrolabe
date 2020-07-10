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
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vmware-tanzu/astrolabe/pkg/astrolabe"
	"github.com/vmware/govmomi/cns"
	cnstypes "github.com/vmware/govmomi/cns/types"
	vim25types "github.com/vmware/govmomi/vim25/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestProtectedEntityTypeManager(t *testing.T) {
	var vcUrl url.URL
	vcUrl.Scheme = "https"
	vcUrl.Host = "10.160.127.39"
	vcUrl.User = url.UserPassword("administrator@vsphere.local", "Admin!23")
	vcUrl.Path = "/sdk"

	t.Logf("%s\n", vcUrl.String())

	ivdPETM, err := NewIVDProtectedEntityTypeManagerFromURL(&vcUrl, astrolabe.S3Config{URLBase: "/ivd"}, true, logrus.New())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	pes, err := ivdPETM.GetProtectedEntities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("# of PEs returned = %d\n", len(pes))
}

func getVcConfigFromParams(params map[string]interface{}) (*url.URL, bool, error) {
	var vcUrl url.URL
	vcUrl.Scheme = "https"
	vcHostStr, err := GetVirtualCenterFromParamsMap(params)
	if err != nil {
		return nil, false, err
	}
	vcHostPortStr, err := GetPortFromParamsMap(params)
	if err != nil {
		return nil, false, err
	}

	vcUrl.Host = fmt.Sprintf("%s:%s", vcHostStr, vcHostPortStr)

	vcUser, err := GetUserFromParamsMap(params)
	if err != nil {
		return nil, false, err
	}
	vcPassword, err := GetPasswordFromParamsMap(params)
	if err != nil {
		return nil, false, err
	}
	vcUrl.User = url.UserPassword(vcUser, vcPassword)
	vcUrl.Path = "/sdk"

	insecure, err := GetInsecureFlagFromParamsMap(params)

	return &vcUrl, insecure, nil
}

func GetVcUrlFromConfig(config *rest.Config) (*url.URL, bool, error) {
	params := make(map[string]interface{})

	err := RetrievePlatformInfoFromConfig(config, params)
	if err != nil {
		return nil, false, errors.Errorf("Failed to retrieve VC config secret: %+v", err)
	}

	vcUrl, insecure, err := getVcConfigFromParams(params)
	if err != nil {
		return nil, false, errors.Errorf("Failed to get VC config from params: %+v", err)
	}

	return vcUrl, insecure, nil
}

func verifyMdIsRestoredAsExpected(md metadata, version string, logger logrus.FieldLogger) bool {
	var reservedLabels []string
	if strings.Contains(version, "6.7U3") {
		reservedLabels = []string{
			"cns.clusterID",
			"cns.clusterType",
			"cns.vSphereUser",
			"cns.k8s.pvName",
			"cns.tag",
		}
	} else if strings.HasPrefix(version, "7.0") {
		reservedLabels = []string{
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

	ctx := context.Background()

	// Step 1: To create the IVD PETM, get all PEs and select one as the reference.
	vcUrl, insecure, err := GetVcUrlFromConfig(config)
	if err != nil {
		t.Fatalf("Failed to get VC config from params: %+v", err)
	}

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	ivdPETM, err := NewIVDProtectedEntityTypeManagerFromURL(vcUrl, astrolabe.S3Config{URLBase: "/ivd"}, insecure, logger)
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
			Config: vim25types.VStorageObjectConfigInfo{
				BaseConfigInfo: vim25types.BaseConfigInfo{
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

	ivdParams := make(map[string]interface{})
	err = RetrievePlatformInfoFromConfig(config, ivdParams)
	if err != nil {
		t.Fatalf("Failed to retrieve VC config secret: %+v", err)
	}

	volumeId, err := createCnsVolumeWithClusterConfig(ctx, ivdParams, config, ivdPETM.client, ivdPETM.cnsClient, md, logger)
	if err != nil {
		t.Fatal("Fail to provision a new volume")
	}

	t.Logf("CNS volume, %v, created", volumeId)
	var volumeIDListToDelete []cnstypes.CnsVolumeId
	volumeIDList = append(volumeIDListToDelete, cnstypes.CnsVolumeId{Id: volumeId})

	defer func() {
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
	}()

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

	ctx := context.Background()

	// Step 1: To create the IVD PETM, get all PEs and select one as the reference.
	vcUrl, insecure, err := GetVcUrlFromConfig(config)
	if err != nil {
		t.Fatalf("Failed to get VC config from params: %+v", err)
	}

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	ivdPETM, err := NewIVDProtectedEntityTypeManagerFromURL(vcUrl, astrolabe.S3Config{URLBase: "/ivd"}, insecure, logger)
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

	ivdParams := make(map[string]interface{})
	err = RetrievePlatformInfoFromConfig(config, ivdParams)
	if err != nil {
		t.Fatalf("Failed to retrieve VC config secret: %+v", err)
	}

	t.Logf("PE name, %v", md.VirtualStorageObject.Config.Name)
	md = FilterLabelsFromMetadataForCnsAPIs(md, "cns", logger)
	volumeId, err := createCnsVolumeWithClusterConfig(ctx, ivdParams, config, ivdPETM.client, ivdPETM.cnsClient, md, logger)
	if err != nil {
		t.Fatal("Fail to provision a new volume")
	}

	t.Logf("CNS volume, %v, created", volumeId)
	var volumeIDListToDelete []cnstypes.CnsVolumeId
	volumeIDList = append(volumeIDListToDelete, cnstypes.CnsVolumeId{Id: volumeId})

	defer func() {
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
	}()

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
