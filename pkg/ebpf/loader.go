package ebpf

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/achevuru/aws-eks-nodeagent/api/v1alpha1"
	"github.com/achevuru/aws-eks-nodeagent/pkg/utils"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
	goebpf "github.com/jayanthvn/pure-gobpf/pkg/ebpf"
	awsperfcgo "github.com/jayanthvn/pure-gobpf/pkg/ebpf_perf_cgo"
	goelf "github.com/jayanthvn/pure-gobpf/pkg/elfparser"
	"k8s.io/apimachinery/pkg/types"
	"net"
	ctrl "sigs.k8s.io/controller-runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

var (
	TC_INGRESS_BINARY = "tc.ingress.bpf.o"
	TC_EGRESS_BINARY  = "tc.egress.bpf.o"
	TC_PROG_SECTION   = "tc_cls"
	TC_INGRESS_PROG   = "handle_ingress"
	TC_EGRESS_PROG    = "handle_egress"
	cwl               *cloudwatchlogs.CloudWatchLogs
	logGroupName      = "NetworkPolicyLogs"
	logStreamName     = ""
	sequenceToken     = ""
)

type BpfClient interface {
	AttacheBPFProbes(pod types.NamespacedName, policyEndpoint string, ingress bool, egress bool) error
	DetacheBPFProbes(pod types.NamespacedName, ingress bool, egress bool) error
	UpdateEbpfMap(bpfPgm *goelf.BPFParser, firewallRules []EbpfFirewallRules, ingress bool) error
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

type Program struct {
	bpfParser *goelf.BPFParser
	pe        *awsperfcgo.PerfEvents
	wg        sync.WaitGroup
}

type Event_t struct {
	SourceIP   uint32
	SourcePort uint32
	DestIP     uint32
	DestPort   uint32
	Protocol   uint32
	Verdict    uint32
}

func setupCW() {
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region: aws.String("us-west-2"),
		},
	})

	if err != nil {
		panic(err)
	}

	cwl = cloudwatchlogs.New(sess)

	err = ensureLogGroupExists(logGroupName)
	if err != nil {
		panic(err)
	}

}

func (l *bpfClient) AttacheBPFProbes(pod types.NamespacedName, podIdentifier string, ingress bool, egress bool) error {
	// We attach the TC probes to the hostVeth interface of the pod. Derive the hostVeth
	// name from the Name and Namespace of the Pod.
	// Note: The below naming convention is tied to VPC CNI and isn't meant to be generic
	hostVethName := l.getHostVethName(pod)
	l.logger.Info("AttachIngressProbe for", "pod", pod.Name, " in namespace", pod.Namespace, " with hostVethName", hostVethName)

	if ingress {
		_, err := l.attachIngressBPFProbe(hostVethName, podIdentifier)
		if err != nil {
			l.logger.Info("Failed to Attach Ingress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
		}
		l.logger.Info("Successfully attached Ingress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
		//ingressProgEntry := goebpf.BPFProgram{ingressProgFd, ""}
		//l.policyEndpointIngressMap.Store(podIdentifier, ingressProgEntry)
	}

	if egress {
		_, err := l.attachEgressBPFProbe(hostVethName, podIdentifier)
		if err != nil {
			l.logger.Info("Failed to Attach Egress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
		}
		l.logger.Info("Successfully attached Egress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
		//egressProgEntry := goebpf.BPFProgram{egressProgFd, ""}
		//l.policyEndpointEgressMap.Store(podIdentifier, egressProgEntry)
	}

	return nil
}

func (l *bpfClient) DetacheBPFProbes(pod types.NamespacedName, ingress bool, egress bool) error {
	hostVethName := l.getHostVethName(pod)
	l.logger.Info("DetachIngressProbe for", "pod", pod.Name, " in namespace", pod.Namespace, " with hostVethName", hostVethName)
	podIdentifier, _ := utils.GetPodIdentifier(pod.Name, pod.Namespace)
	if ingress {
		err := l.detachIngressBPFProbe(hostVethName)
		if err != nil {
			l.logger.Info("Failed to Detach Ingress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
		}
		l.logger.Info("Successfully detached Ingress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
		//ingressProgEntry := goebpf.BPFProgram{ingressProgFd, ""}
		l.policyEndpointIngressMap.Delete(podIdentifier)
	}

	if egress {
		err := l.detachEgressBPFProbe(hostVethName)
		if err != nil {
			l.logger.Info("Failed to Detach Egress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
		}
		l.logger.Info("Successfully detached Egress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
		l.policyEndpointEgressMap.Delete(podIdentifier)
	}

	return nil
}

func (l *bpfClient) attachIngressBPFProbe(hostVethName string, podIdentifier string) (int, error) {
	// We will re-use the same eBPF program instance for pods belonging to same replicaset
	// Check if we've already loaded an ELF file for this PolicyEndpoint resource and re-use
	// if present, otherwise load a new instance and attach it
	var progFD, mapFD int
	value, ok := l.policyEndpointIngressMap.Load(podIdentifier)
	if ok {
		l.logger.Info("Found an existing instance")
		ingressEbpfProgEntry := value.(goelf.BPFParser)
		progFD = ingressEbpfProgEntry.ElfContext.Section[TC_PROG_SECTION].Programs[TC_EGRESS_PROG].ProgFD
	} else { //!ok
		l.logger.Info("Load new instance of the eBPF program")
		// Load a new instance of the ingress program
		elfInfo, err := goelf.LoadBpfFile(TC_EGRESS_BINARY)
		if err != nil {
			l.logger.Info("Load BPF failed", "err:", err)
		}

		progFD = (*elfInfo).ElfContext.Section["tc_cls"].Programs["handle_egress"].ProgFD
		mapFD = int((*elfInfo).ElfContext.Maps["egress_map"].MapFD)

		//ingressProgEntry := goebpf.BPFProgram{progFD, ""}
		ingressProgEntry := elfInfo //goebpf.BPFParser{progFD, ""}
		l.logger.Info("Ingress Prog Load Succeeded", "progFD for handle_egress: ", progFD, "mapFD: ", mapFD)
		l.policyEndpointIngressMap.Store(podIdentifier, ingressProgEntry)
		l.bpfProgMap.Store(progFD, mapFD)
	}

	l.logger.Info("Attempting to do an Ingress Attach")
	err := goebpf.TCIngressAttach(hostVethName, progFD)
	if err != nil {
		l.logger.Info("Ingress Attach failed:", "error", err)
	}

	return progFD, nil
}

func (l *bpfClient) attachEgressBPFProbe(hostVethName string, podIdentifier string) (int, error) {
	// We will re-use the same eBPF program instance for pods belonging to same replicaset
	// Check if we've already loaded an ELF file for this PolicyEndpoint resource and re-use
	// if present, otherwise load a new instance and attach it

	var progFD, mapFD int
	value, ok := l.policyEndpointEgressMap.Load(podIdentifier)
	if ok {
		l.logger.Info("Found an existing instance")
		egressEbpfProgEntry := value.(goelf.BPFParser)
		progFD = egressEbpfProgEntry.ElfContext.Section[TC_PROG_SECTION].Programs[TC_INGRESS_PROG].ProgFD
	} else { //!ok
		l.logger.Info("Load new instance of the eBPF program")
		// Load a new instance of the ingress program
		elfInfo, err := goelf.LoadBpfFile(TC_INGRESS_BINARY)
		if err != nil {
			l.logger.Info("Load BPF failed", "err:", err)
		}
		p := Program{bpfParser: elfInfo}

		progFD = (*elfInfo).ElfContext.Section["tc_cls"].Programs["handle_ingress"].ProgFD
		mapFD = int((*elfInfo).ElfContext.Maps["ingress_map"].MapFD)

		egressProgEntry := elfInfo
		l.logger.Info("Egress Prog Load Succeeded", "progFD for handle_ingress: ", progFD, " mapFD: ", mapFD)
		l.policyEndpointEgressMap.Store(podIdentifier, egressProgEntry)
		l.bpfProgMap.Store(progFD, mapFD)

		if mapToUpdate, ok := (*elfInfo).ElfContext.Maps["events"]; ok {
			var err error
			p.pe, err = awsperfcgo.NewPerfEvents(int(mapToUpdate.MapFD), (*elfInfo).BpfMapAPIs)
			if err != nil {
				return -1, err
			}
			events, err := p.pe.StartForAllProcessesAndCPUs(4096)
			if err != nil {
				return -1, err
			}

			// start event listeners
			p.wg = sync.WaitGroup{}
			p.startPerfEvents(events, l.logger)
			setupCW()
		}
	}

	l.logger.Info("Attempting to do an Egress Attach")
	err := goebpf.TCEgressAttach(hostVethName, progFD)
	if err != nil {
		l.logger.Info("Egress Attach failed:", "error", err)
	}

	return progFD, nil
}

func (l *bpfClient) detachIngressBPFProbe(hostVethName string) error {
	l.logger.Info("Attempting to do an Ingress Detach")
	err := goebpf.TCIngressDetach(hostVethName)
	if err != nil {
		l.logger.Info("Ingress Detach failed:", "error", err)
		return err
	}
	return nil
}

func (l *bpfClient) detachEgressBPFProbe(hostVethName string) error {
	l.logger.Info("Attempting to do an Egress Detach")
	err := goebpf.TCEgressDetach(hostVethName)
	if err != nil {
		l.logger.Info("Ingress Detach failed:", "error", err)
		return err
	}
	return nil
}

type EbpfFirewallRules struct {
	IPCidr []v1alpha1.NetworkPeer
	L4Info []v1alpha1.Port
}

func (l *bpfClient) UpdateEbpfMap(bpfPgm *goelf.BPFParser, firewallRules []EbpfFirewallRules,
	ingress bool) error {

	var progFD int
	if ingress {
		progFD = (*bpfPgm).ElfContext.Section["tc_cls"].Programs["handle_egress"].ProgFD
	} else {
		progFD = (*bpfPgm).ElfContext.Section["tc_cls"].Programs["handle_ingress"].ProgFD
	}
	l.logger.Info("Map Update - Prog", "FD:", progFD)
	cacheValue, _ := l.bpfProgMap.Load(progFD)
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
				err := (*bpfPgm).BpfMapAPIs.UpdateMapEntry(uintptr(unsafe.Pointer(&key[0])), uintptr(unsafe.Pointer(&value[0])),
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
	protocol := 6 //string(*l4Info.Protocol)
	var startPort int
	endPort := 65535

	if l4Info.Port != nil {
		startPort = (*l4Info.Port).IntValue()
	}

	if l4Info.EndPort != nil {
		endPort = int(*l4Info.EndPort)
	}

	l.logger.Info("L4 values: ", "protocol: ", protocol, "startPort: ", startPort, "endPort: ", endPort)
	// Key format: Prefix length (4 bytes) followed by 4 byte IP
	value := make([]byte, 12)

	binary.LittleEndian.PutUint32(value[0:4], uint32(protocol))
	binary.LittleEndian.PutUint32(value[4:8], uint32(startPort))
	binary.LittleEndian.PutUint32(value[8:12], uint32(endPort))

	return value
}

func (p *Program) startPerfEvents(events <-chan []byte, log logr.Logger) {
	p.wg.Add(1)
	go func(events <-chan []byte) {
		defer p.wg.Done()

		for {
			if b, ok := <-events; ok {

				var ev Event_t
				var logQueue []*cloudwatchlogs.InputLogEvent
				buf := bytes.NewBuffer(b)
				if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
					log.Error(err, "Failed to read buf")
					continue
				}

				tokens := bytes.Split(buf.Bytes(), []byte{0x00})
				var args []string
				for _, arg := range tokens {
					if len(arg) > 0 {
						args = append(args, string(arg))
					}
				}

				var desc string
				if len(args) > 0 {
					desc = args[0]
				}
				if len(args) > 2 {
					desc += " " + strings.Join(args[2:], " ")
				}

				log.Info("Kprobe", "Src IP", convByteArrayToIP(ev.SourceIP))
				log.Info("Kprobe", "Dest IP", convByteArrayToIP(ev.DestIP))
				log.Info("Kprobe", "Src Port", ev.SourcePort)
				log.Info("Kprobe", "Dest Port", ev.DestPort)

				protocol := "UNKNOWN"
				if ev.Protocol == 6 {
					protocol = "TCP"
				} else if ev.Protocol == 17 {
					protocol = "UDP"
				} else if ev.Protocol == 1 {
					protocol = "ICMP"
				}

				log.Info("Kprobe", "Proto", ev.Protocol)
				log.Info("Kprobe", "Verdict", ev.Verdict)
				verdict := "DENY"
				if ev.Verdict == 1 {
					verdict = "ACCEPT"
				}
				message := "SIP: " + convByteArrayToIP(ev.SourceIP) + ";" + "SPORT: " + strconv.Itoa(int(ev.SourcePort)) + ";" + "DIP: " + convByteArrayToIP(ev.DestIP) + ";" + "DPORT: " + strconv.Itoa(int(ev.DestPort)) + ";" + "PROTOCOL: " + protocol + ";" + "PolicyVerdict: " + verdict
				logQueue = append(logQueue, &cloudwatchlogs.InputLogEvent{
					Message:   &message,
					Timestamp: aws.Int64(time.Now().UnixNano() / int64(time.Millisecond)),
				})
				if len(logQueue) > 0 {
					log.Info("Sending CW")
					input := cloudwatchlogs.PutLogEventsInput{
						LogEvents:    logQueue,
						LogGroupName: &logGroupName,
					}

					if sequenceToken == "" {
						err := createLogStream()
						if err != nil {
							log.Info("Failed to create log stream")
							panic(err)
						}
					} else {
						input = *input.SetSequenceToken(sequenceToken)
					}

					input = *input.SetLogStreamName(logStreamName)

					resp, err := cwl.PutLogEvents(&input)
					if err != nil {
						log.Info("Kprobe", "Failed ", err)
					}

					if resp != nil {
						sequenceToken = *resp.NextSequenceToken
					}

					logQueue = []*cloudwatchlogs.InputLogEvent{}
				}
			} else {
				break
			}
		}
	}(events)
}

func ensureLogGroupExists(name string) error {
	resp, err := cwl.DescribeLogGroups(&cloudwatchlogs.DescribeLogGroupsInput{})
	if err != nil {
		return err
	}

	for _, logGroup := range resp.LogGroups {
		if *logGroup.LogGroupName == name {
			return nil
		}
	}

	_, err = cwl.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: &name,
	})
	if err != nil {
		return err
	}
	return err
}

func createLogStream() error {
	name := uuid.New().String()

	_, err := cwl.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  &logGroupName,
		LogStreamName: &name,
	})

	logStreamName = name
	return err
}

func convByteArrayToIP(ipInInt uint32) string {
	hexIPString := fmt.Sprintf("%x", ipInInt)

	byteData, _ := hex.DecodeString(hexIPString)
	reverseByteData := reverseByteArray(byteData)

	return strings.Trim(strings.Join(strings.Fields(fmt.Sprint(reverseByteData)), "."), "[]")
}

func reverseByteArray(input []byte) []byte {
	if len(input) == 0 {
		return input
	}
	return append(reverseByteArray(input[1:]), input[0])
}
