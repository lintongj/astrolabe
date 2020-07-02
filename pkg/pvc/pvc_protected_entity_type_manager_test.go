package pvc

import (
	"context"
	"github.com/sirupsen/logrus"
	"github.com/vmware-tanzu/astrolabe/pkg/astrolabe"
	"github.com/vmware-tanzu/astrolabe/pkg/fs"
	"github.com/vmware-tanzu/astrolabe/pkg/ivd"
	"github.com/vmware-tanzu/astrolabe/pkg/kubernetes"
	"log"
	"os"
	"testing"
)

type DirectProtectedEntityManager struct {
	typeManager map[string]astrolabe.ProtectedEntityTypeManager
	s3Config    astrolabe.S3Config
}

func NewDirectProtectedEntityManager(petms []astrolabe.ProtectedEntityTypeManager, s3Config astrolabe.S3Config) (returnPEM *DirectProtectedEntityManager) {
	returnPEM = &DirectProtectedEntityManager{
		typeManager: make(map[string]astrolabe.ProtectedEntityTypeManager),
	}
	for _, curPETM := range petms {
		returnPEM.typeManager[curPETM.GetTypeName()] = curPETM
		switch curPETM.(type) {
		case *PVCProtectedEntityTypeManager:
			curPETM.(*PVCProtectedEntityTypeManager).SetProtectedEntityManager(returnPEM)
		}
	}
	returnPEM.s3Config = s3Config
	return
}

func NewDirectProtectedEntityManagerFromParamMap(configInfo ConfigInfo) *DirectProtectedEntityManager {
	petms := make([]astrolabe.ProtectedEntityTypeManager, 0) // No guarantee all configs will be valid, so don't preallocate
	var err error
	logger := logrus.New()
	for serviceName, params := range configInfo.peConfigs {
		var curService astrolabe.ProtectedEntityTypeManager
		switch serviceName {
		case "ivd":
			curService, err = ivd.NewIVDProtectedEntityTypeManagerFromConfig(params, configInfo.s3Config, logger)
		case "k8sns":
			curService, err = kubernetes.NewKubernetesNamespaceProtectedEntityTypeManagerFromConfig(params, configInfo.s3Config,
				logger)
		case "fs":
			curService, err = fs.NewFSProtectedEntityTypeManagerFromConfig(params, configInfo.s3Config, logger)
		case "pvc":
			curService, err = NewPVCProtectedEntityTypeManagerFromConfig(params, configInfo.s3Config, logger)
		default:

		}
		if err != nil {
			log.Printf("Could not start service %s err=%v", serviceName, err)
			continue
		}
		if curService != nil {
			petms = append(petms, curService)
		}
	}
	return NewDirectProtectedEntityManager(petms, configInfo.s3Config)
}

func (this *DirectProtectedEntityManager) GetProtectedEntity(ctx context.Context, id astrolabe.ProtectedEntityID) (astrolabe.ProtectedEntity, error) {
	return this.typeManager[id.GetPeType()].GetProtectedEntity(ctx, id)
}

func (this *DirectProtectedEntityManager) GetProtectedEntityTypeManager(peType string) astrolabe.ProtectedEntityTypeManager {
	return this.typeManager[peType]
}

func (this *DirectProtectedEntityManager) ListEntityTypeManagers() []astrolabe.ProtectedEntityTypeManager {
	returnArr := []astrolabe.ProtectedEntityTypeManager{}
	for _, curPETM := range this.typeManager {
		returnArr = append(returnArr, curPETM)
	}
	return returnArr
}

func NewConfigInfo(peConfigs map[string]map[string]interface{}, s3Config astrolabe.S3Config) ConfigInfo {
	return ConfigInfo{
		peConfigs: peConfigs,
		s3Config:  s3Config,
	}
}

type ConfigInfo struct {
	peConfigs map[string]map[string]interface{}
	s3Config  astrolabe.S3Config
}

func TestInit(t *testing.T) {
	pvcParams :=make(map[string]interface{})
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	pvcParams["kubeconfigPath"] = home + "/.kube/config"

	config := make(map[string]map[string]interface{})
	config["pvc"] = pvcParams

	ivdParams := make(map[string]interface{})
	ivdParams["VirtualCenter"] = "10.208.22.169"
	ivdParams["insecureVC"] = "Y"
	ivdParams["user"] = "administrator@vsphere.local"
	ivdParams["password"] = "Admin!23"
	ivdParams["port"] = "443"
	ivdParams["insecure-flag"] = "true"

	config["ivd"] = ivdParams
	// Largely a dummy s3Config - s3Config is to enable access to astrolabe objects via S3 which we don't support from
	// here
	s3Config := astrolabe.S3Config{
		Port:      0,
		Host:      nil,
		AccessKey: "",
		Secret:    "",
		Prefix:    "",
		URLBase:   "VOID_URL",
	}

	configInfo := NewConfigInfo(config, s3Config)

	pem := NewDirectProtectedEntityManagerFromParamMap(configInfo)

	pvc_petm := pem.GetProtectedEntityTypeManager("pvc")
	if pvc_petm == nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	peids, err := pvc_petm.GetProtectedEntities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, curPEID := range peids {
		curPE, err := pvc_petm.GetProtectedEntity(ctx, curPEID)
		if err != nil {
			t.Fatal(err)
		}
		curPE.GetComponents(ctx)
	}
}
