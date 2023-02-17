package ebpf

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/go-logr/logr"
	goebpf "github.com/jayanthvn/pure-gobpf/pkg/ebpf"
	goelf "github.com/jayanthvn/pure-gobpf/pkg/elfparser"
	corev1 "k8s.io/api/core/v1"
	"net"
	ctrl "sigs.k8s.io/controller-runtime"
	"strings"
	"sync"
	"unsafe"
)

//"k8s.aws/aws-vpc-policy-controller/pkg/k8s"

type BpfClient interface {
	AttacheBPFProbes(pod *corev1.Pod, policyEndpoint string, ingress bool, egress bool) error
	UpdateEbpfMap(bpfPgm goebpf.BPFProgram, cidrEntries []string) error
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

func (l *bpfClient) AttacheBPFProbes(pod *corev1.Pod, policyEndpoint string, ingress bool, egress bool) error {
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

func (l *bpfClient) UpdateEbpfMap(bpfPgm goebpf.BPFProgram, cidrEntries []string) error {

	value, _ := l.bpfProgMap.Load(bpfPgm.ProgFD)
	mapFD := value.(int)
	l.logger.Info("Update Map", "FD:", mapFD)
	for _, addr := range cidrEntries {
		if !strings.Contains(addr, "/") {
			addr += "/32"
		}
		l.logger.Info("adding to ingress_map", "addr", addr)
		_, toAllow, _ := net.ParseCIDR(addr)
		l.logger.Info("parsed", "addr", toAllow)
		key := toKey(*toAllow)
		index := 0
		err := bpfPgm.UpdateMapEntry(uintptr(unsafe.Pointer(&key[0])), uintptr(unsafe.Pointer(&index)),
			uint32(mapFD))
		if err != nil {
			l.logger.Info("BPF map update failed", "error: ", err)
		}
	}

	return nil
}

func (l *bpfClient) getHostVethName(pod *corev1.Pod) string {
	h := sha1.New()
	h.Write([]byte(fmt.Sprintf("%s.%s", pod.Namespace, pod.Name)))
	return fmt.Sprintf("%s%s", "eni", hex.EncodeToString(h.Sum(nil))[:11])
}

func toKey(n net.IPNet) []byte {
	prefixLen, _ := n.Mask.Size()

	// Key format: Prefix length (4 bytes) followed by 4 byte IP
	key := make([]byte, 4+4)

	binary.LittleEndian.PutUint32(key[0:4], uint32(prefixLen))
	copy(key[4:], n.IP)

	return key
}
