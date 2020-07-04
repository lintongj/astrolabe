package pvc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
"github.com/sirupsen/logrus"
	"github.com/vmware-tanzu/astrolabe/pkg/astrolabe"
	"io"
	"io/ioutil"
	core_v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

/*
PVCProtectedEntity implements a Protected Entity interface to PVCs and a basic local snapshot facility.  The PVC
has a component PE which will be the PE that maps to the volume referenced by the PVC.  Currently IVD and para-virt PV
are available

The PVC at the time of the snapshot is serialized and stored in a config map in the namespace named
pvc-snap.<pvc name>.  Each snapshot has an entry in the binary data map for the serialized PVC data, named by the
snapshot ID (this is the snapshot ID returned by the subcomponent)
 */
type PVCProtectedEntity struct {
	ppetm     *PVCProtectedEntityTypeManager
	id        astrolabe.ProtectedEntityID
	data      []astrolabe.DataTransport
	metadata  []astrolabe.DataTransport
	combined  []astrolabe.DataTransport
	logger    logrus.FieldLogger
}

func newPVCProtectedEntity(ppetm *PVCProtectedEntityTypeManager, peid astrolabe.ProtectedEntityID) (PVCProtectedEntity, error) {
	if peid.GetPeType() != pvcPEType {
		return PVCProtectedEntity{}, errors.New(fmt.Sprintf("%s is not a PVC PEID", peid.String()))
	}
	returnPPE := PVCProtectedEntity{
		ppetm: ppetm,
		id: peid,
	}
	return returnPPE, nil
}

func (this PVCProtectedEntity) GetInfo(ctx context.Context) (astrolabe.ProtectedEntityInfo, error) {
	pvc, err := this.getPVC()
	if err != nil {
		return nil, errors.Wrap(err, "Could not retrieve PVC")
	}
	components, err := this.GetComponents(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "Could not retrieve component")
	}
	retPEInfo := astrolabe.NewProtectedEntityInfo(this.id, pvc.Name, this.data, this.metadata, this.combined,
		[]astrolabe.ProtectedEntityID{components[0].GetID()})
	return retPEInfo, nil
}

func (this PVCProtectedEntity) GetCombinedInfo(ctx context.Context) ([]astrolabe.ProtectedEntityInfo, error) {
	panic("implement me")
}

func (this PVCProtectedEntity) Snapshot(ctx context.Context) (astrolabe.ProtectedEntitySnapshotID, error) {
	if this.id.HasSnapshot() {
		return astrolabe.ProtectedEntitySnapshotID{}, errors.New("Cannot create snapshot of snapshot")
	}
	pvc, err := this.getPVC()
	if err != nil {
		return astrolabe.ProtectedEntitySnapshotID{}, errors.Wrap(err, "Could not retrieve pvc")
	}
	components, err := this.GetComponents(ctx)
	if err != nil {
		return astrolabe.ProtectedEntitySnapshotID{}, errors.Wrap(err, "Could not retrieve components")
	}
	if len(components) != 1 {
		return astrolabe.ProtectedEntitySnapshotID{}, errors.New(fmt.Sprintf("Expected 1 component, %s has %d", this.id.String(), len(components)))
	}
	subSnapshotID, err := components[0].Snapshot(ctx)
	if err != nil {
		return astrolabe.ProtectedEntitySnapshotID{}, errors.Wrapf(err, "Subcomponent peid %s snapshot failed", components[0].GetID())
	}

	snapshotPEID := astrolabe.NewProtectedEntityIDWithSnapshotID(this.id.GetPeType(), this.id.GetID(), subSnapshotID)
	snapConfigMapName := getSnapConfigMapName(pvc)
	snapConfigMap, err := this.ppetm.clientSet.CoreV1().ConfigMaps(pvc.Namespace).Get(snapConfigMapName, metav1.GetOptions{})
	var binaryData map[string][]byte
	var create bool
	if err != nil {
		if !k8serrors.IsNotFound(err) {
			return astrolabe.ProtectedEntitySnapshotID{}, errors.Wrapf(err, "Could not retrieve snapshot configmap %s for %s", snapConfigMapName,
				this.id.String())
		}
		binaryData = make(map[string][]byte)

		snapConfigMap = &core_v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:                       snapshotPEID.String(),
				Namespace:                  pvc.Namespace,
			},
			BinaryData: binaryData,
		}
		create = true
	} else {
		binaryData = snapConfigMap.BinaryData
	}
	pvcData, err := pvc.Marshal()
	if err != nil {
		return astrolabe.ProtectedEntitySnapshotID{}, errors.Wrapf(err, "Could not marshal PVC data for ",
			this.id.String())
	}
	binaryData[subSnapshotID.String()] = pvcData
	peInfo, err := this.GetInfo(ctx)
	if err != nil {
		return astrolabe.ProtectedEntitySnapshotID{}, errors.Wrapf(err, "Could not retrieve PE info for ",
			this.id.String())
	}
	peInfoData, err := json.Marshal(peInfo)
	if err != nil {
		return astrolabe.ProtectedEntitySnapshotID{}, errors.Wrapf(err, "Marshal peid info %s failed", components[0].GetID())
	}

	binaryData["peinfo-"+subSnapshotID.String()] = peInfoData
	if create {
		_, err = this.ppetm.clientSet.CoreV1().ConfigMaps(pvc.Namespace).Create(snapConfigMap)
	} else {
		_, err = this.ppetm.clientSet.CoreV1().ConfigMaps(pvc.Namespace).Update(snapConfigMap)
	}
	if err != nil {
		return astrolabe.ProtectedEntitySnapshotID{}, errors.Wrapf(err, "PVC Snapshot write peid %s failed", components[0].GetID())
	}
	return subSnapshotID, nil
}

func (this PVCProtectedEntity) ListSnapshots(ctx context.Context) ([]astrolabe.ProtectedEntitySnapshotID, error) {
	if this.id.HasSnapshot() {
		return nil, errors.New("Cannot create snapshot of snapshot")
	}
	pvc, err := this.getPVC()
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Could not retrieve pvc peid=%s", this.id.String()))
	}
	snapConfigMapName := getSnapConfigMapName(pvc)
	snapConfigMap, err := this.ppetm.clientSet.CoreV1().ConfigMaps(pvc.Namespace).Get(snapConfigMapName, metav1.GetOptions{})
	if err != nil {
		if !k8serrors.IsNotFound(err) {
			return nil, errors.Wrapf(err, "Could not retrieve snapshot configmap %s for %s", snapConfigMapName,
				this.id.String())
		}
		// No configmap so no snapshots
		return []astrolabe.ProtectedEntitySnapshotID{}, nil
	}
	returnIDs := make([]astrolabe.ProtectedEntitySnapshotID, 0)
	for snapshotIDStr, _ := range snapConfigMap.BinaryData {
		returnIDs = append(returnIDs, astrolabe.NewProtectedEntitySnapshotID(snapshotIDStr))
	}
	return returnIDs, nil
}

func getSnapConfigMapName(pvc *core_v1.PersistentVolumeClaim) string {
	return "pvc-snap." + pvc.Name
}

func (this PVCProtectedEntity) DeleteSnapshot(ctx context.Context, snapshotToDelete astrolabe.ProtectedEntitySnapshotID) (bool, error) {
	if this.id.HasSnapshot() {
		return false, errors.New("Cannot delete snapshot of snapshot")
	}
	pvc, err := this.getPVC()
	if err != nil {
		return false, errors.Wrap(err, fmt.Sprintf("Could not retrieve pvc peid=%s", this.id.String()))
	}
	snapConfigMapName := getSnapConfigMapName(pvc)
	snapConfigMap, err := this.ppetm.clientSet.CoreV1().ConfigMaps(pvc.Namespace).Get(snapConfigMapName, metav1.GetOptions{})
	if err != nil {
		if !k8serrors.IsNotFound(err) {
			return false, errors.Wrapf(err, "Could not retrieve snapshot configmap %s for %s", snapConfigMapName,
				this.id.String())
		}
		// No configmap so no snapshots
		return false, nil
	}

	_, snapPVCInfoExists := snapConfigMap.BinaryData[snapshotToDelete.String()]
	if snapPVCInfoExists {
		delete(snapConfigMap.BinaryData, snapshotToDelete.GetID())
		_, err = this.ppetm.clientSet.CoreV1().ConfigMaps(pvc.Namespace).Update(snapConfigMap)
		if err != nil {
			return false, errors.Wrapf(err, "Could not update snapshot configmap %s for %s", snapConfigMapName,
				this.id.String())
		}
	}
	components, err := this.GetComponents(ctx)
	if err != nil {
		return false, errors.Wrap(err, "Could not retrieve components")
	}
	if len(components) != 1 {
		return false, errors.New(fmt.Sprintf("Expected 1 component, %s has %d", this.id.String(), len(components)))
	}
	subSnapshots, err := components[0].ListSnapshots(ctx)
	if err != nil {
		return false, errors.Wrapf(err, "Subcomponent peid %s list snapshot", components[0].GetID())
	}
	subsnapshotExists := false
	for _, checkSnapshot := range subSnapshots {
		if checkSnapshot == snapshotToDelete {
			subsnapshotExists = true
			break
		}
	}

	if subsnapshotExists {
		_, err := components[0].DeleteSnapshot(ctx, snapshotToDelete)
		if err != nil {
			return false, errors.Wrapf(err, "Subcomponent peid %s snapshot failed", components[0].GetID())
		}
	}

	// If either the configmap info existed or the subsnapshot existed, then we successfully removed, otherwise
	// there was no work (errors would have exited us already) so we return false
	return subsnapshotExists || snapPVCInfoExists, nil
}

func (this PVCProtectedEntity) GetInfoForSnapshot(ctx context.Context, snapshotID astrolabe.ProtectedEntitySnapshotID) (*astrolabe.ProtectedEntityInfo, error) {
	panic("implement me")
}

func (this PVCProtectedEntity) GetComponents(ctx context.Context) ([]astrolabe.ProtectedEntity, error) {
	pvc, err := this.getPVC()
	if err != nil {
		return nil, errors.Wrap(err, "Could not retrieve PVC")
	}

	if pvc.Status.Phase != core_v1.ClaimBound {
		return []astrolabe.ProtectedEntity{}, nil
	}

	pv, err := this.ppetm.clientSet.CoreV1().PersistentVolumes().Get(pvc.Spec.VolumeName, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "Could not retrieve Persistent Volume")
	}
	fmt.Printf("pv=%v\n", pv)	// TODO - remove me!
	pvPE, err := this.getProtectedEntityForPV(ctx, pv)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not find subcomponent PEID for %s %s %s", this.id.String(), pvc.Namespace, pvc.Name)
	}
	return []astrolabe.ProtectedEntity{pvPE}, nil
}

func (this PVCProtectedEntity) getProtectedEntityForPV(ctx context.Context, pv *core_v1.PersistentVolume) (astrolabe.ProtectedEntity, error) {
	if pv.Spec.CSI != nil {
		if pv.Spec.CSI.Driver == "csi.vsphere.vmware.com" {
			if pv.Spec.AccessModes[0] == core_v1.ReadWriteOnce {
				ivdPEID := astrolabe.NewProtectedEntityIDWithSnapshotID("ivd", pv.Spec.CSI.VolumeHandle, this.id.GetSnapshotID())
				ivdPE, err := this.ppetm.pem.GetProtectedEntity(ctx , ivdPEID)
				if err != nil {
					return nil, errors.Wrapf(err, "Could not get Protected Entity for ivd %s", ivdPEID.String())
				}
				return ivdPE, nil
			}
		}
	}
	return nil, errors.New(fmt.Sprintf("Could not find PE for %s %s", pv.Namespace, pv.Name))
}
func (this PVCProtectedEntity) GetID() astrolabe.ProtectedEntityID {
	return this.id
}

func (this PVCProtectedEntity) GetDataReader(ctx context.Context) (io.ReadCloser, error) {
	return nil, nil
}

func (this PVCProtectedEntity) GetMetadataReader(ctx context.Context) (io.ReadCloser, error) {
	if this.id.HasSnapshot() {
		panic("Fix me - snapshot MD retrieval not implemented")
	}
	pvc, err := this.getPVC()
	if err != nil {
		return nil, errors.Wrapf(err,"Could not get pvc")
	}
	pvcBytes, err := pvc.Marshal()
	return ioutil.NopCloser(bytes.NewReader(pvcBytes)), nil
}

func (this PVCProtectedEntity) getPVC() (*core_v1.PersistentVolumeClaim, error) {
	namespace, name, err := GetNamespaceAndNameFromPEID(this.id)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not get namespace and id from PEID %s", this.id.String())
	}
	pvc, err := this.ppetm.clientSet.CoreV1().PersistentVolumeClaims(namespace).Get(name, metav1.GetOptions{

	})
	if err != nil {
		return nil, errors.Wrapf(err, "Could not get retrieve pvc with namespace %s, id %s", namespace, name)
	}
	return pvc, nil
}
