/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	policyk8sawsv1 "github.com/achevuru/aws-eks-nodeagent/api/v1alpha1"
	"github.com/achevuru/aws-eks-nodeagent/pkg/ebpf"
	"github.com/achevuru/aws-eks-nodeagent/pkg/utils"
	"github.com/achevuru/aws-eks-nodeagent/pkg/utils/imds"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sync"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	goelf "github.com/jayanthvn/pure-gobpf/pkg/elfparser"

	"github.com/go-logr/logr"
)

// NewPolicyEndpointsReconciler constructs new PolicyEndpointReconciler
func NewPolicyEndpointsReconciler(k8sClient client.Client, log logr.Logger) *PolicyEndpointsReconciler {
	r := &PolicyEndpointsReconciler{
		K8sClient: k8sClient,
		Log:       log,
	}
	r.ebpfClient = ebpf.NewBpfClient(&r.bpfProgMap, &r.policyEndpointIngressMap, &r.policyEndpointEgressMap)
	r.nodeIP, _ = imds.GetMetaData("local-ipv4")

	return r
}

// PolicyEndpointsReconciler reconciles a PolicyEndpoints object
type PolicyEndpointsReconciler struct {
	K8sClient client.Client
	Scheme    *runtime.Scheme
	nodeIP    string
	//Maps eBPF Program FC to Map FD
	bpfProgMap sync.Map
	// Maps PolicyEndpoint resource to Ingress eBPF Program FD
	policyEndpointIngressMap sync.Map
	// Maps PolicyEndpoint resource to Egress eBPF Program FD
	policyEndpointEgressMap sync.Map
	// Maps PolicyEndpoint resource with a list of pods that are already serviced
	policyEndpointSelectorMap sync.Map

	ebpfClient ebpf.BpfClient

	Log logr.Logger
}

//+kubebuilder:rbac:groups=policy.k8s.aws.nodeagent,resources=policyendpoints,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=policy.k8s.aws.nodeagent,resources=policyendpoints/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=policy.k8s.aws.nodeagent,resources=policyendpoints/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *PolicyEndpointsReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.Log.Info("Got reconcile request", "req", req)

	if err := r.reconcile(ctx, req); err != nil {
		r.Log.Info("Reconcile error, requeueing", "err", err)
		return ctrl.Result{Requeue: true}, nil
	}

	return ctrl.Result{}, nil
	//return runtime.HandleReconcileError(r.reconcile(req), r.log)
}

func (r *PolicyEndpointsReconciler) reconcile(ctx context.Context, req ctrl.Request) error {
	//ctx := context.Background()
	policyEndpoint := &policyk8sawsv1.PolicyEndpoints{}

	r.Log.Info("Get Policy Endpoint spec for", "name", req.NamespacedName.Name)
	if err := r.K8sClient.Get(ctx, req.NamespacedName, policyEndpoint); err != nil {
		if err1 := client.IgnoreNotFound(err); err1 == nil {
			return r.cleanUpPolicyEndpoint(ctx, policyEndpoint, req)
		}
		return client.IgnoreNotFound(err)
	}
	r.Log.Info("Successfully derived Policy Endpoint spec for", "name", req.NamespacedName.Name)

	if !policyEndpoint.DeletionTimestamp.IsZero() {
		return r.cleanUpPolicyEndpoint(ctx, policyEndpoint, req)
	}

	return r.reconcilePolicyEndpoint(ctx, policyEndpoint, req)
}

func (r *PolicyEndpointsReconciler) cleanUpPolicyEndpoint(ctx context.Context,
	policyEndpoint *policyk8sawsv1.PolicyEndpoints, req ctrl.Request) error {

	r.Log.Info("Clean Up PolicyEndpoint resources for", "name:", req.NamespacedName.Name)
	policyEndpointIdentifier := req.NamespacedName.Namespace + req.NamespacedName.Name
	if targetPods, ok := r.policyEndpointSelectorMap.Load(policyEndpointIdentifier); ok {
		for _, targetPod := range targetPods.([]types.NamespacedName) {
			r.ebpfClient.DetacheBPFProbes(targetPod, true, true)
		}
	}

	return nil
}

func (r *PolicyEndpointsReconciler) reconcilePolicyEndpoint(ctx context.Context,
	policyEndpoint *policyk8sawsv1.PolicyEndpoints, req ctrl.Request) error {
	ingress, egress, existingPod := false, false, false
	var podsList []types.NamespacedName

	//Derive Ingress IPs from the PolicyEndpoint
	//ingressCIDRs, egressCIDRs, err := r.deriveIngressAndEgressCIDRs(ctx, policyEndpoint)
	ingressRules, egressRules, err := r.deriveIngressAndEgressFirewallRules(ctx, policyEndpoint)
	if err != nil {
		r.Log.Info("Error Parsing policy Endpoint resource", "name:", req.NamespacedName.Name)
	}

	if len(ingressRules) > 0 {
		ingress = true
	}

	if len(egressRules) > 0 {
		egress = true
	}

	// Derive pods
	// and filter based on the Pod selector. If PodSelector is empty, then the policy applies to
	// all the pods under the namespace
	r.Log.Info("Get Pods from the policy endpoint resource: ", "in namespace", req.NamespacedName.Name)
	r.Log.Info("Node IP - ", "Node IP:", r.nodeIP)

	targetPods, err := r.deriveTargetPods(ctx, policyEndpoint)
	//Loop over target pods and setup/configure eBPF probes/maps
	for _, pod := range targetPods {
		r.Log.Info("Pod: ", "name:", pod.Name, "namespace:", pod.Namespace)
		policyEndpointIdentifier := utils.GetPolicyEndpointIdentifier(req.NamespacedName.Name,
			req.NamespacedName.Namespace)
		podIdentifier, _ := utils.GetPodIdentifier(pod.Name, pod.Namespace)
		r.Log.Info("PolicyEndpoint Identifier: ", "Identifer: ", policyEndpointIdentifier)
		r.Log.Info("Map Identifier: ", "Pod Identifer: ", podIdentifier)

		//Check if we've already processed this pod against this policyEndpoint resource
		if knownPodsList, ok := r.policyEndpointSelectorMap.Load(policyEndpointIdentifier); ok {
			for _, podID := range knownPodsList.([]types.NamespacedName) {
				if podID.Name+podID.Namespace == pod.Name+pod.Namespace {
					//Note: Update to this PE resource can have both new pods and new endpoints
					//and since we share the maps across these pods, updating the map as part of new
					//endpoint processing will take care of that.
					existingPod = true
					break
				}
			}
			podsList = knownPodsList.([]types.NamespacedName)
		}

		if existingPod {
			r.Log.Info("Existing pod against this PE resource. Nothing to do. Pod: ", "name:", pod.Name, "namespace:", pod.Namespace)
			continue
		}

		err := r.ebpfClient.AttacheBPFProbes(pod, podIdentifier, ingress, egress)
		if err != nil {
			r.Log.Info("Attaching eBPF probe failed for", "pod:", pod.Name, "in namespace", pod.Namespace)
		}
		r.Log.Info("Successfully attached required eBPF probes for", "pod:", pod.Name, "in namespace", pod.Namespace)

		ingressValue, ok := r.policyEndpointIngressMap.Load(podIdentifier)
		if ok {
			ingressBpfPgm := ingressValue.(*goelf.BPFParser)
			//Update Ingress eBPF Map
			if err = r.ebpfClient.UpdateEbpfMap(ingressBpfPgm, egressRules, true); err != nil {
				r.Log.Info("Updating Ingress eBPF map failed for", "pod:", pod.Name, "in namespace", pod.Namespace)
			}
		}

		egressValue, ok := r.policyEndpointEgressMap.Load(podIdentifier)
		if ok {
			egressBpfPgm := egressValue.(*goelf.BPFParser)
			//Update Egress eBPF Map
			if err = r.ebpfClient.UpdateEbpfMap(egressBpfPgm, ingressRules, false); err != nil {
				r.Log.Info("Updating Egress eBPF map failed for", "pod:", pod.Name, "in namespace", pod.Namespace)
			}
		}

		podsList = append(podsList, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace})
		r.policyEndpointSelectorMap.Store(policyEndpointIdentifier, podsList)
		existingPod = false
	}

	return nil
}

func (r *PolicyEndpointsReconciler) deriveIngressAndEgressFirewallRules(ctx context.Context,
	policyEndpoint *policyk8sawsv1.PolicyEndpoints) ([]ebpf.EbpfFirewallRules, []ebpf.EbpfFirewallRules, error) {
	var ingressRules, egressRules []ebpf.EbpfFirewallRules

	for _, cidrList := range policyEndpoint.Spec.Ingress {
		ingressRules = append(ingressRules,
			ebpf.EbpfFirewallRules{
				IPCidr: cidrList.From,
				L4Info: cidrList.Ports,
			})
	}

	for _, cidrList := range policyEndpoint.Spec.Egress {
		egressRules = append(egressRules,
			ebpf.EbpfFirewallRules{
				IPCidr: cidrList.To,
				L4Info: cidrList.Ports,
			})
	}

	return ingressRules, egressRules, nil
}

func (r *PolicyEndpointsReconciler) deriveTargetPods(ctx context.Context,
	policyEndpoint *policyk8sawsv1.PolicyEndpoints) ([]types.NamespacedName, error) {
	var targetPods []types.NamespacedName

	// Pods are grouped by Host IP. Individual node agents will need to filter pods
	// that have the same Host IP value as the node IP of the node where it is running.
	for _, pod := range policyEndpoint.Spec.PodSelectorEndpoints {
		if r.nodeIP == string(pod.HostIP) {
			r.Log.Info("Found a matching Pod: ", "name: ", pod.Name, "namespace: ", pod.Namespace)
			targetPods = append(targetPods, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace})
		}
	}
	return targetPods, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PolicyEndpointsReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policyk8sawsv1.PolicyEndpoints{}).
		Complete(r)
}
