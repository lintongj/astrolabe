package ivd

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/cns"
	cnstypes "github.com/vmware/govmomi/cns/types"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	vim25types "github.com/vmware/govmomi/vim25/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// vSphere constants
const (
	DefaultVcHostPort = "443"
)

func findDataCenterFromAncestors(ctx context.Context, client *vim25.Client, objectRef vim25types.ManagedObjectReference, logger logrus.FieldLogger) (string, error)  {
	pc := property.DefaultCollector(client)
	path, err := mo.Ancestors(ctx, client, pc.Reference(), objectRef)
	if err != nil {
		return "", err
	}
	for i := range path {
		if path[i].Reference().Type == "Datacenter" {
			logger.Debugf("Object reference=%v, DC=%v", objectRef, path[i].Name)
			return path[i].Name, nil
		}
	}
	return "", errors.New("Failed to find the datacenter from ancestors")
}

func findHostsOfNodeVMs(ctx context.Context, client *vim25.Client, config *rest.Config, logger logrus.FieldLogger) ([]vim25types.ManagedObjectReference, error) {
	// #1: get hostNames of all node VMs
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	nodeList, err := clientSet.CoreV1().Nodes().List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	vmHostNameMap := make(map[string]bool)
	for _, node := range nodeList.Items {
		if node.Name == "" {
			return nil, errors.Errorf("One of the node VM with uid, %v, in the cluster has empty node name", node.UID)
		}
		vmHostNameMap[node.Name] = true
	}

	// #2: go through the VM list in this VC and get their host from vm.runtime
	finder := find.NewFinder(client)

	dcs, err := finder.DatacenterList(ctx, "*")
	if err != nil {
		logger.WithError(err).Error("Failed to find the list of data centers in VC")
		return nil, err
	}

	var vmRefList []vim25types.ManagedObjectReference
	for _, dc := range dcs {
		path := fmt.Sprintf("%v/vm/...", dc.InventoryPath)
		vms, err := finder.VirtualMachineList(ctx, path)
		if err != nil {
			logger.WithError(err).Error("Failed to find the list of VMs in a data center")
			return nil, err
		}

		for _, vm := range vms {
			vmRefList = append(vmRefList, vm.Reference())
		}
	}

	logger.Debugf("vmRefList = %v", vmRefList)

	pc := property.DefaultCollector(client)
	var vmMoList []mo.VirtualMachine
	err = pc.Retrieve(ctx, vmRefList, []string{"runtime", "guest"}, &vmMoList)
	if err != nil {
		logger.WithError(err).Error("Failed to retrieve VM runtime and guest properties")
		return nil, err
	}

	var hostList []vim25types.ManagedObjectReference
	hostRefMap := make(map[vim25types.ManagedObjectReference]bool)
	for _, vmMo := range vmMoList {
		_, ok := vmHostNameMap[vmMo.Guest.HostName]
		if !ok {
			continue
		}

		_, ok = hostRefMap[*vmMo.Runtime.Host]
		if !ok {
			hostRefMap[*vmMo.Runtime.Host] = true
			hostList = append(hostList, *vmMo.Runtime.Host)
		}
	}

	logger.Debugf("hostList = %v", hostList)
	return hostList, nil
}

func findSharedDatastoresFromAllNodeVMs(ctx context.Context, client *vim25.Client, config *rest.Config, logger logrus.FieldLogger) ([]vim25types.ManagedObjectReference, error) {
	finder := find.NewFinder(client)


	hosts, err := findHostsOfNodeVMs(ctx, client, config, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to find hosts of all node VMs")
		return nil, err
	}
	nHosts := len(hosts)
	if nHosts <= 0 {
		logger.WithError(err).Error("No hosts can be found for node VMs")
		return nil, errors.New("No hosts can be found for node VMs")
	}

	dcNameMap := make(map[string]bool)
	for _, host := range hosts {
		dcName, err := findDataCenterFromAncestors(ctx, client, host.Reference(), logger)
		if err != nil {
			logger.Debugf("Failed to find a datacenter from ancestors of VM, %v", host.Reference())
			continue
		}
		_, ok := dcNameMap[dcName]
		if !ok {
			dcNameMap[dcName] = true
		}
	}

	var dss []*object.Datastore
	for dcName, _ := range dcNameMap {
		path := fmt.Sprintf("/%v/datastore/*", dcName)
		dssPerDC, err := finder.DatastoreList(ctx, path)
		if err != nil {
			logger.WithError(err).Error("Failed to find the list of all datastores in VC")
			return nil, err
		}
		dss = append(dss, dssPerDC...)
	}

	var dsList []vim25types.ManagedObjectReference
	for _, ds := range dss {
		dsType, err := ds.Type(ctx)
		if err != nil {
			logger.WithError(err).Warnf("Failed to get type of datastore %v", ds.Reference())
			continue
		}

		if dsType == vim25types.HostFileSystemVolumeFileSystemTypeNFS41 {
			// Currently, provisioning PV on NFS 4.1 datastore is not officially supported.
			// It will be turned on once it is supported.
			continue
		}

		if dsType == vim25types.HostFileSystemVolumeFileSystemTypeNFS {
			var dsMo mo.Datastore
			err = ds.Properties(ctx, ds.Reference(), []string{"info"}, &dsMo)
			if err != nil {
				logger.WithError(err).Warnf("Failed to get info of datastore %v", ds.Reference())
				continue
			}
			logger.Debugf("NFS name = %v", dsMo.Info.GetDatastoreInfo().Name)
			nasDsInfo, ok := dsMo.Info.(*vim25types.NasDatastoreInfo)
			if !ok {
				logger.Debugf("Failed to get info of NFS datastore %v", ds.Reference())
				continue
			}
			logger.Debugf("NAS RemoteHost = %v", nasDsInfo.Nas.RemoteHost)
			if strings.Contains(nasDsInfo.Nas.RemoteHost, "eng.vmware.com") {
				logger.Debugf("Detected a VMware specific NFS volume, %v. Skipping it", nasDsInfo.Name)
				continue
			}
		}

		attachedHosts, err := ds.AttachedHosts(ctx)
		if err != nil {
			logger.WithError(err).Warnf("Failed to get all the attached hosts of datastore %v", ds.Reference())
			continue
		}

		if len(attachedHosts) < nHosts {
			continue
		}

		// make the array of attached hosts a map of attached hosts for the convenience of look-up
		attachedHostsMap := make(map[vim25types.ManagedObjectReference]vim25types.ManagedObjectReference)
		for _, host := range attachedHosts {
			attachedHostsMap[host.Reference()] = ds.Reference()
		}

		// traverse the hosts of node VMs and filter out datastores that are not accessible from any host of node VMs
		eligible := true
		for _, host := range hosts {
			_, ok := attachedHostsMap[host.Reference()]
			if !ok {
				eligible = false
				break
			}
		}

		if eligible {
			dsList = append(dsList, ds.Reference())
		}
	}

	logger.Debugf("Shared datastores from all node VMs: %v", dsList)
	return dsList, nil
}

func retrievePlatformInfoFromConfig(config *rest.Config, params map[string]interface{}, logger logrus.FieldLogger) error {
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.WithError(err).Errorf("Failed to get k8s clientSet from the given config: %v", config)
		return err
	}

	namespaces := []string{"kube-system", "vmware-system-csi"}
	vsphere_secret := "vsphere-config-secret"
	var secret *v1.Secret
	for _, ns := range namespaces {
		secretApis := clientSet.CoreV1().Secrets(ns)

		secret, err = secretApis.Get(vsphere_secret, metav1.GetOptions{})
		if err == nil {
			logger.Infof("Succeeded to get k8s secret, %s, from the namespace, %s", vsphere_secret, ns)
			break
		}
		logger.Debugf("Failed to get k8s secret, %s, from the namespace, %s. Keep trying.", vsphere_secret, ns)
	}

	if err != nil {
		logger.Errorf("Failed to find k8s secret, %s, from any of the namespaces, %v", vsphere_secret, namespaces)
		return err
	}

	conf_keys := []string{"csi-vsphere.conf", "vsphere-cloud-provider.conf"}
	var sEnc string
	for _, conf_key := range conf_keys {
		conf_value, ok := secret.Data[conf_key]
		if ok {
			logger.Infof("Succeeded to find one of the expected key, %v, for the secret data", conf_key)
			sEnc = string(conf_value)
			break
		}
		logger.Debugf("the conf key, %s, cannot be found. Keep trying.", conf_key)
	}

	if sEnc == "" {
		logger.Errorf("Failed to find any expected key, %v, for the secret data", conf_keys)
		return err
	}

	lines := strings.Split(sEnc, "\n")

	var vcRgx = regexp.MustCompile(`\[(.*?) (.*?)\]`)
	for _, line := range lines {
		if strings.Contains(line, "VirtualCenter") {
			rs := vcRgx.FindStringSubmatch(line)
			vcIpWithQuotes := rs[len(rs) - 1]
			unquotedVcIp, err := strconv.Unquote(string(vcIpWithQuotes))
			if err != nil {
				logger.Warnf("Failed to unquote the VirtualCenter hostname from the VC credential")
				continue
			}
			params["VirtualCenter"] = unquotedVcIp
		} else if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			unquotedValue, err := strconv.Unquote(string(value))
			if err != nil {
				continue
			}
			params[key] = unquotedValue
		}
	}

	logger.Debugf("Params: %v", params)

	return nil
}

func createCnsVolumeWithClusterConfig(ctx context.Context, config *rest.Config, client *govmomi.Client, cnsClient *cns.Client, md metadata, logger logrus.FieldLogger) (string, error) {
	logger.Debugf("createCnsVolumeWithClusterConfig called with args, metadata: %v", md)

	reservedLabelsMap, err := fillInClusterSpecificParams(config, logger)
	if err != nil {
		logger.WithError(err).Error("Failed at calling fillInClusterSpecificParams")
		return "", err
	}

	// Preparing for the VolumeCreateSpec for the volume provisioning
	logger.Debug("Preparing for the VolumeCreateSpec for the volume provisioning")
	dsList, err := findSharedDatastoresFromAllNodeVMs(ctx, client.Client, config, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to find any datastore in the underlying vSphere")
		return "", err
	}

	var metadataList []cnstypes.BaseCnsEntityMetadata
	metadata := &cnstypes.CnsKubernetesEntityMetadata{
		CnsEntityMetadata: cnstypes.CnsEntityMetadata{
			EntityName:  md.VirtualStorageObject.Config.Name,
			Labels:      md.ExtendedMetadata,
		},
		EntityType: string(cnstypes.CnsKubernetesEntityTypePV),
	}
	metadataList = append(metadataList, cnstypes.BaseCnsEntityMetadata(metadata))

	var cnsVolumeCreateSpecList []cnstypes.CnsVolumeCreateSpec
	cnsVolumeCreateSpec := cnstypes.CnsVolumeCreateSpec{
		Name:        md.VirtualStorageObject.Config.Name,
		VolumeType: string(cnstypes.CnsVolumeTypeBlock),
		Datastores: dsList,
		Metadata: cnstypes.CnsVolumeMetadata{
			ContainerCluster: cnstypes.CnsContainerCluster{
				ClusterType: string(cnstypes.CnsClusterTypeKubernetes), // hard coded for the moment
				ClusterId:   reservedLabelsMap["cns.containerCluster.clusterId"],
				VSphereUser: reservedLabelsMap["cns.containerCluster.vSphereUser"],
			},
			EntityMetadata: metadataList,
		},
		BackingObjectDetails: &cnstypes.CnsBlockBackingDetails{
			CnsBackingObjectDetails: cnstypes.CnsBackingObjectDetails{
				CapacityInMb: md.VirtualStorageObject.Config.CapacityInMB,
			},
		},
	}

	cnsVolumeCreateSpecList = append(cnsVolumeCreateSpecList, cnsVolumeCreateSpec)
	logger.Debugf("Provisioning volume using the spec: %v", cnsVolumeCreateSpec)

	// provision volume using CNS API
	createTask, err := cnsClient.CreateVolume(ctx, cnsVolumeCreateSpecList)
	if err != nil {
		logger.WithError(err).Errorf("Failed to create volume. Error: %+v", err)
		return "", err
	}
	createTaskInfo, err := cns.GetTaskInfo(ctx, createTask)
	if err != nil {
		logger.WithError(err).Errorf("Failed to create volume. Error: %+v", err)
		return "", err
	}
	createTaskResult, err := cns.GetTaskResult(ctx, createTaskInfo)
	if err != nil {
		logger.WithError(err).Errorf("Failed to create volume. Error: %+v", err)
		return "", err
	}
	if createTaskResult == nil {
		err := errors.New("Empty create task results")
		logger.Error(err.Error())
		return "", err
	}
	createVolumeOperationRes := createTaskResult.GetCnsVolumeOperationResult()
	if createVolumeOperationRes.Fault != nil {
		logger.Errorf("Failed to create volume: fault=%+v", createVolumeOperationRes.Fault)
		return "", errors.New(createVolumeOperationRes.Fault.LocalizedMessage)
	}

	volumeId := createVolumeOperationRes.VolumeId.Id
	logger.Infof("CNS volume, %v, created", volumeId)
	return volumeId, nil
}

func fillInClusterSpecificParams(config *rest.Config, logger logrus.FieldLogger) (map[string]string, error) {
	params := make(map[string]interface{})
	err := retrievePlatformInfoFromConfig(config, params, logger)
	if err != nil {
		logger.WithError(err).Errorf("Failed to retrieve VC config secret: %+v", err)
		return map[string]string{}, err
	}

	clusterId, ok := params["cluster-id"].(string)
	if !ok {
		logger.WithError(err).Errorf("Failed to retrieve cluster id")
		return map[string]string{}, err
	}

	user, ok := params["user"].(string)
	if !ok {
		logger.WithError(err).Errorf("Failed to retrieve vsphere user")
		return map[string]string{}, err
	}
	logger.Debugf("Retrieved cluster id, %v, and vSphere user, %v", clusterId, user)

	// currently, we only pick up two cluster specific labels, cluster-id and vsphere-user.
	// For the following labels,
	//    cns.containerCluster.clusterType -- always "KUBERNETES", and no other type available for the moment
	//    cns.containerCluster.clusterFlavor -- the most recent govmomi version doesn't provide field to set the cluster flavor
	//    others are not cluster specfic, but cns specific
	reservedLabelsMap := map[string]string {
		//"cns.containerCluster.clusterFlavor",
		//"cns.containerCluster.clusterType",
		//"cns.k8s.pv.name",
		//"cns.tag",
		//"cns.version",
		"cns.containerCluster.clusterId": clusterId,
		"cns.containerCluster.vSphereUser": user,
	}

	return reservedLabelsMap, nil
}

func FilterLabelsFromMetadataForVslmAPIs(md metadata, logger logrus.FieldLogger) (metadata, error) {
	var kvsList []vim25types.KeyValue

	logger.Debugf("labels of CNS volume before filtering: %v", md.ExtendedMetadata)

	// Retrieving cluster id and vSphere user
	logger.Debug("Retrieving cluster id and vSphere user required by provisioning volume")
	config, err := rest.InClusterConfig()
	if err != nil {
		logger.WithError(err).Error("Failed to get k8s inClusterConfig")
		return metadata{}, err
	}

	reservedLabelsMap, err := fillInClusterSpecificParams(config, logger)
	if err != nil {
		logger.WithError(err).Error("Failed at calling fillInClusterSpecificParams")
		return metadata{}, err
	}

	for key, value := range reservedLabelsMap {
		kvsList = append(kvsList, vim25types.KeyValue {
			Key: key,
			Value: value,
		})
	}

	for _, label := range md.ExtendedMetadata {
		value, ok := reservedLabelsMap[label.Key]
		if !ok {
			value = label.Value
		}
		kvsList = append(kvsList, vim25types.KeyValue {
			Key: label.Key,
			Value: value,
		})
	}
	md.ExtendedMetadata = kvsList

	logger.Debugf("labels of CNS volume after filtering: %v", md.ExtendedMetadata)

	return md, nil
}

func FilterLabelsFromMetadataForCnsAPIs(md metadata, prefix string, logger logrus.FieldLogger) metadata {
	// prefix: cns.containerCluster
	var kvsList []vim25types.KeyValue

	logger.Debugf("labels of CNS volume before filtering ones with certain prefix, %v: %v", prefix, md.ExtendedMetadata)

	for _, label := range md.ExtendedMetadata {
		if !strings.HasPrefix(label.Key, prefix) {
			kvsList = append(kvsList, vim25types.KeyValue {
				Key: label.Key,
				Value: label.Value,
			})
		}
	}
	md.ExtendedMetadata = kvsList

	logger.Debugf("labels of CNS volume after filtering ones with certain prefix, %v: %v", prefix, md.ExtendedMetadata)

	return md
}

func CreateCnsVolumeInCluster(ctx context.Context, client *govmomi.Client, cnsClient *cns.Client, md metadata, logger logrus.FieldLogger) (vim25types.ID, error) {
	logger.Infof("CreateCnsVolumeInCluster called with args, metadata: %v", md)

	// Retrieving cluster id and vSphere user
	logger.Debug("Retrieving cluster id and vSphere user required by provisioning volume")
	config, err := rest.InClusterConfig()
	if err != nil {
		logger.WithError(err).Error("Failed to get k8s inClusterConfig")
		return vim25types.ID{}, err
	}

	volumeId, err := createCnsVolumeWithClusterConfig(ctx, config, client, cnsClient, md, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to call createCnsVolumeWithClusterConfig")
		return vim25types.ID{}, err
	}

	return NewIDFromString(volumeId), nil
}

func getVcConfigFromParams(params map[string]interface{}) (*url.URL, bool, error) {
	var vcUrl url.URL
	vcUrl.Scheme = "https"
	vcHostStr, ok := params["VirtualCenter"].(string)
	if !ok {
		return nil, false, errors.New("Missing vcHost param")
	}
	vcHostPortStr, ok := params["port"].(string)
	if !ok {
		vcHostPortStr = DefaultVcHostPort
	}
	vcUrl.Host = fmt.Sprintf("%s:%s", vcHostStr, vcHostPortStr)

	vcUser, ok := params["user"].(string)
	if !ok {
		return nil, false, errors.New("Missing vcUser param")
	}
	vcPassword, ok := params["password"].(string)
	if !ok {
		return nil, false, errors.New("Missing vcPassword param")
	}
	vcUrl.User = url.UserPassword(vcUser, vcPassword)
	vcUrl.Path = "/sdk"

	insecure := false
	insecureStr, ok := params["insecure-flag"].(string)
	if ok && (insecureStr == "TRUE" || insecureStr == "true") {
		insecure = true
	}

	return &vcUrl, insecure, nil
}

func GetVcUrlFromConfig(config *rest.Config, logger logrus.FieldLogger) (*url.URL, bool, error) {
	params := make(map[string]interface{})

	err := retrievePlatformInfoFromConfig(config, params, logger)
	if err != nil {
		return nil, false, errors.Errorf("Failed to retrieve VC config secret: %+v", err)
	}

	vcUrl, insecure, err := getVcConfigFromParams(params)
	if err != nil {
		return nil, false, errors.Errorf("Failed to get VC config from params: %+v", err)
	}

	return vcUrl, insecure, nil
}