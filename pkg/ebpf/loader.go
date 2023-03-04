package ebpf

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/achevuru/aws-eks-nodeagent/api/v1alpha1"
	"github.com/go-logr/logr"
	goebpf "github.com/jayanthvn/pure-gobpf/pkg/ebpf"
	goelf "github.com/jayanthvn/pure-gobpf/pkg/elfparser"
	"k8s.io/apimachinery/pkg/types"
	"net"
	ctrl "sigs.k8s.io/controller-runtime"
	"strings"
	"sync"
	"unsafe"
)

type BpfClient interface {
	AttacheBPFProbes(pod types.NamespacedName, policyEndpoint string, ingress bool, egress bool) error
	UpdateEbpfMap(bpfPgm goebpf.BPFProgram, firewallRules []EbpfFirewallRules) error
}

func NewBpfClient(bpfProgMap *sync.Map, policyEndpointIngressMap *sync.Map,
	policyEndpointEgressMap *sync.Map) *bpfClient {
	return &bpfClient{
		bpfProgMap:               bpfProgMap,
		policyEndpointIngressMap: policyEndpointIngressMap,
		policyEndpointEgressMap:  policyEndpointEgressMap,
		logger:                   ctrl.Log.WithName("ebpf-client"),
	}
}

var _ BpfClient = (*bpfClient)(nil)

type bpfClient struct {
	bpfProgMap               *sync.Map
	policyEndpointIngressMap *sync.Map
	policyEndpointEgressMap  *sync.Map
	logger                   logr.Logger
}

func (l *bpfClient) AttacheBPFProbes(pod types.NamespacedName, policyEndpoint string, ingress bool, egress bool) error {
	// We attach the TC probes to the hostVeth interface of the pod. Derive the hostVeth
	// name from the Name and Namespace of the Pod.
	// Note: The below naming convention is tied to VPC CNI and isn't meant to be generic
	hostVethName := l.getHostVethName(pod)
	l.logger.Info("AttachIngressProbe for", "pod", pod.Name, " in namespace", pod.Namespace, " with hostVethName", hostVethName)

	if ingress {
		ingressProgFd, err := l.attachIngressBPFProbe(hostVethName, policyEndpoint)
		if err != nil {
			l.logger.Info("Failed to Attach Ingress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
		}
		l.logger.Info("Successfully attached Ingress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
		ingressProgEntry := goebpf.BPFProgram{ingressProgFd, ""}
		l.policyEndpointIngressMap.Store(policyEndpoint, ingressProgEntry)
	}

	if egress {
		egressProgFd, err := l.attachEgressBPFProbe(hostVethName, policyEndpoint)
		if err != nil {
			l.logger.Info("Failed to Attach Ingress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
		}
		l.logger.Info("Successfully attached Egress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
		egressProgEntry := goebpf.BPFProgram{egressProgFd, ""}
		l.policyEndpointEgressMap.Store(policyEndpoint, egressProgEntry)
	}

	return nil
}

func (l *bpfClient) attachIngressBPFProbe(hostVethName string, policyEndpoint string) (int, error) {
	// We will re-use the same eBPF program instance for pods belonging to same replicaset
	// Check if we've already loaded an ELF file for this PolicyEndpoint resource and re-use
	// if present, otherwise load a new instance and attach it
	var progFD, mapFD int
	value, ok := l.policyEndpointIngressMap.Load(policyEndpoint)
	if ok {
		l.logger.Info("Found an existing instance")
		progFD = value.(int)
	} else { //!ok
		l.logger.Info("Load new instance of the eBPF program")
		// Load a new instance of the ingress program
		elfInfo, err := goelf.LoadBpfFile("tc.egress.bpf.o")
		if err != nil {
			l.logger.Info("Load BPF failed", "err:", err)
		}

		progFD = (*elfInfo).Section["tc_cls"].Programs["handle_egress"].ProgFD
		mapFD = int((*elfInfo).Maps["egress_map"].MapFD)

		progEntry := goebpf.BPFProgram{progFD, ""}
		l.logger.Info("Ingress Prog Load Succeeded", "progFD for handle_egress: ", progFD, "mapFD: ", mapFD)
		l.policyEndpointIngressMap.Store(policyEndpoint, progEntry)
		l.bpfProgMap.Store(progFD, mapFD)
	}

	l.logger.Info("Attempting to do an Ingress Attach")
	err := goebpf.TCIngressAttach(hostVethName, progFD)
	if err != nil {
		l.logger.Info("Ingress Attach failed:", "error", err)
	}

	return progFD, nil
}

func (l *bpfClient) attachEgressBPFProbe(hostVethName string, policyEndpoint string) (int, error) {
	// We will re-use the same eBPF program instance for pods belonging to same replicaset
	// Check if we've already loaded an ELF file for this PolicyEndpoint resource and re-use
	// if present, otherwise load a new instance and attach it

	var progFD, mapFD int
	value, ok := l.policyEndpointEgressMap.Load(policyEndpoint)
	if ok {
		l.logger.Info("Found an existing instance")
		progFD = value.(int)
	} else { //!ok
		l.logger.Info("Load new instance of the eBPF program")
		// Load a new instance of the ingress program
		elfInfo, err := goelf.LoadBpfFile("tc.ingress.bpf.o")
		if err != nil {
			l.logger.Info("Load BPF failed", "err:", err)
		}

		progFD = (*elfInfo).Section["tc_cls"].Programs["handle_ingress"].ProgFD
		mapFD = int((*elfInfo).Maps["ingress_map"].MapFD)

		progEntry := goebpf.BPFProgram{progFD, ""}
		l.logger.Info("Egress Prog Load Succeeded", "progFD for handle_ingress: ", progFD, " mapFD: ", mapFD)
		l.policyEndpointEgressMap.Store(policyEndpoint, progEntry)
		l.bpfProgMap.Store(progFD, mapFD)
	}

	l.logger.Info("Attempting to do an Egress Attach")
	err := goebpf.TCEgressAttach(hostVethName, progFD)
	if err != nil {
		l.logger.Info("Egress Attach failed:", "error", err)
	}

	return progFD, nil
}

type EbpfFirewallRules struct {
	IPCidr []v1alpha1.NetworkPeer
	L4Info []v1alpha1.Port
}

func (l *bpfClient) UpdateEbpfMap(bpfPgm goebpf.BPFProgram, firewallRules []EbpfFirewallRules) error {

	cacheValue, _ := l.bpfProgMap.Load(bpfPgm.ProgFD)
	mapFD := cacheValue.(int)
	l.logger.Info("Update Map", "FD:", mapFD)

	for _, firewallRule := range firewallRules {
		for _, l4Info := range firewallRule.L4Info {
			value := l.toValue(l4Info)
			for _, addr := range firewallRule.IPCidr {
				if !strings.Contains(string(addr.CIDR), "/") {
					addr.CIDR += "/32"
				}
				l.logger.Info("adding to ingress_map", "addr", addr)
				_, mapKey, _ := net.ParseCIDR(string(addr.CIDR))
				l.logger.Info("parsed", "addr", mapKey)
				key := l.toKey(*mapKey)
				//index := 0
				err := bpfPgm.UpdateMapEntry(uintptr(unsafe.Pointer(&key[0])), uintptr(unsafe.Pointer(&value[0])),
					uint32(mapFD))
				if err != nil {
					l.logger.Info("BPF map update failed", "error: ", err)
				}
			}

		}
	}

	return nil
}

func (l *bpfClient) getHostVethName(pod types.NamespacedName) string {
	h := sha1.New()
	h.Write([]byte(fmt.Sprintf("%s.%s", pod.Namespace, pod.Name)))
	return fmt.Sprintf("%s%s", "eni", hex.EncodeToString(h.Sum(nil))[:11])
}

func (l *bpfClient) toKey(n net.IPNet) []byte {
	prefixLen, _ := n.Mask.Size()

	// Key format: Prefix length (4 bytes) followed by 4 byte IP
	key := make([]byte, 8)

	binary.LittleEndian.PutUint32(key[0:4], uint32(prefixLen))
	copy(key[4:], n.IP)

	return key
}

func (l *bpfClient) toValue(l4Info v1alpha1.Port) []byte {
	protocol := 1 //string(*l4Info.Protocol)
	startPort := (*l4Info.Port).IntValue()
	endPort := 0 //*l4Info.EndPort

	l.logger.Info("L4 values: ", "protocol: ", protocol, "startPort: ", startPort, "endPort: ", endPort)
	// Key format: Prefix length (4 bytes) followed by 4 byte IP
	value := make([]byte, 12)

	binary.LittleEndian.PutUint32(value[0:4], uint32(protocol))
	binary.LittleEndian.PutUint32(value[4:8], uint32(startPort))
	binary.LittleEndian.PutUint32(value[8:12], uint32(endPort))

	//copy(value[4:], n.IP)

	return value
}
