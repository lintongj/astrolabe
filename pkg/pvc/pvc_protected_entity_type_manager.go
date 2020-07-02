package pvc

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vmware-tanzu/astrolabe/pkg/astrolabe"
	"github.com/vmware-tanzu/astrolabe/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"strings"
)

type PVCProtectedEntityTypeManager struct {
	clientSet *kubernetes.Clientset
	pem       astrolabe.ProtectedEntityManager
	s3Config  astrolabe.S3Config
}

const pvcPEType = "pvc"

func NewProtectedEntityIDFromPVCName(namespace string, pvcName string) astrolabe.ProtectedEntityID {
	idStr := base64.RawURLEncoding.EncodeToString([]byte(namespace)) + ":" + base64.RawURLEncoding.EncodeToString([]byte(pvcName))
	return astrolabe.NewProtectedEntityID(pvcPEType, idStr)
}

func GetNamespaceAndNameFromPEID(peid astrolabe.ProtectedEntityID) (namespace string, name string, err error) {
	if peid.GetPeType() != pvcPEType {
		return "", "", errors.New(fmt.Sprintf("%s + is not of type %s", peid.GetPeType(), pvcPEType))
	}
	parts := strings.Split(peid.GetID(), ":")
	if len(parts) != 2 {
		return "", "", errors.New(fmt.Sprintf("%s has %d parts, expected 2", peid.GetID(), len(parts)))
	}
	namespaceBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", errors.New(fmt.Sprintf("Could not decode namespace base64 %s", parts[0]))
	}
	namespace = string(namespaceBytes)

	nameBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", errors.New(fmt.Sprintf("Could not decode name base64 %s", parts[1]))
	}
	name = string(nameBytes)
	return
}

func NewPVCProtectedEntityTypeManagerFromConfig(params map[string]interface{}, s3Config astrolabe.S3Config,
	logger logrus.FieldLogger) (*PVCProtectedEntityTypeManager, error) {
	masterURL, _ := util.GetStringFromParamsMap(params, "masterURL", logger)
	kubeconfigPath, _ := util.GetStringFromParamsMap(params, "kubeconfigPath", logger)
	config, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfigPath)
	if err != nil {
		return nil, err
	}
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &PVCProtectedEntityTypeManager{
		clientSet: clientSet,
		s3Config: s3Config,
	}, nil
}

func (this *PVCProtectedEntityTypeManager) SetProtectedEntityManager(pem astrolabe.ProtectedEntityManager) {
	this.pem = pem
}

func (this *PVCProtectedEntityTypeManager) GetTypeName() string {
	return pvcPEType
}

func (this *PVCProtectedEntityTypeManager) GetProtectedEntity(ctx context.Context, peid astrolabe.ProtectedEntityID) (astrolabe.ProtectedEntity, error) {
	namespace, name, err := GetNamespaceAndNameFromPEID(peid)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not get namespace and name from peid %s", peid.String())
	}

	returnPE, err := newPVCProtectedEntity(this, peid)

	if err != nil {
		return nil, errors.Wrapf(err, "Could not create PVCProtectedEntity for namespace = %s, name = %s", namespace, name)
	}

	_, err = returnPE.getPVC()
	if err != nil {
		return nil, errors.Wrapf(err, "Could not retrieve PVC for namespace = %s, name = %s", namespace, name)
	}
	return returnPE, nil
}

func (this *PVCProtectedEntityTypeManager) GetProtectedEntities(ctx context.Context) ([]astrolabe.ProtectedEntityID, error) {
	pvcList, err := this.clientSet.CoreV1().PersistentVolumeClaims("").List(metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "Could not list PVCs")
	}
	retPEIDs := make([]astrolabe.ProtectedEntityID, 0)
	for _, curPVC := range pvcList.Items {
		retPEIDs = append(retPEIDs, NewProtectedEntityIDFromPVCName(curPVC.Namespace, curPVC.Name))
	}
	return retPEIDs, nil
}

func (this *PVCProtectedEntityTypeManager) Copy(ctx context.Context, pe astrolabe.ProtectedEntity, options astrolabe.CopyCreateOptions) (astrolabe.ProtectedEntity, error) {
	panic("implement me")
}

func (this *PVCProtectedEntityTypeManager) CopyFromInfo(ctx context.Context, info astrolabe.ProtectedEntityInfo, options astrolabe.CopyCreateOptions) (astrolabe.ProtectedEntity, error) {
	panic("implement me")
}

func (this *PVCProtectedEntityTypeManager) getDataTransports(id astrolabe.ProtectedEntityID) ([]astrolabe.DataTransport,
	[]astrolabe.DataTransport,
	[]astrolabe.DataTransport, error) {

	data := []astrolabe.DataTransport{}

	mdS3Transport, err := astrolabe.NewS3MDTransportForPEID(id, this.s3Config)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "Could not create S3 md transport")
	}

	md := []astrolabe.DataTransport{
		mdS3Transport,
	}

	combinedS3Transport, err := astrolabe.NewS3CombinedTransportForPEID(id, this.s3Config)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "Could not create S3 combined transport")
	}

	combined := []astrolabe.DataTransport{
		combinedS3Transport,
	}

	return data, md, combined, nil
}