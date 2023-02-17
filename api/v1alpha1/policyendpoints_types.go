/*
Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.

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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// PolicyReference is the reference to the network policy resource
type PolicyReference struct {
	// Name is the name of the Policy
	Name string `json:"name"`

	// Port is the port of the ServicePort.
	Namespace string `json:"namespace"`
}

// +kubebuilder:validation:Enum=TCP;UDP
type Protocol string

type NetworkAddress string

const (
	ProtocolTCP Protocol = "TCP"
	ProtocolUDP Protocol = "UDP"
)

// Port contains information about the transport port/protocol
type Port struct {
	// Protocol specifies the transport protocol, default TCP
	Protocol *Protocol `json:"protocol,omitempty"`

	// Port specifies the numerical or named port for the protocol. If empty, applies to all ports.
	Port *intstr.IntOrString `json:"port,omitempty"`

	// Endport specifies the port range port to endPort
	// port must be defined and an integer, endPort > port
	EndPort *int32 `json:"endPort,omitempty"`
}

type NetworkPeer struct {
	// CIDR specifies the network address(es) of the endpoint.
	CIDR NetworkAddress `json:"cidr"`

	// Except is the exceptions to the CIDR ranges mentioned above.
	// The exception must be within the specified CIDR range.
	Except []NetworkAddress `json:"except,omitempty"`
}

type IngressRule struct {
	// Ports is the list of ports
	Ports []Port `json:"ports,omitempty"`
	// From is the list of network IP/CIDR addresses
	From []NetworkPeer `json:"from,omitempty"`
}

type EgressRule struct {
	// Ports is the list of ports
	Ports []Port `json:"ports,omitempty"`
	// To is the list of network IP/CIDR addresses
	To []NetworkPeer `json:"from,omitempty"`
}

// PolicyEndpointsSpec defines the desired state of PolicyEndpoints
type PolicyEndpointsSpec struct {
	// PodSelector is the podSeletor from the policy resource
	PodSelector *metav1.LabelSelector `json:"podSelector"`

	// PodSelectorEndpoints is the resolved pod addresses corresponding
	// to the podSelector
	PodSelectorEndpoints []NetworkAddress `json:"podSelectorEndpoints"`

	// policyRef is a reference to the Kubernetes Policy resource.
	PolicyRef PolicyReference `json:"policyRef"`

	// PolicyType is the type of the policy, ingress or egress
	// +kubebuilder: validation: Enum=Ingress;Egress
	PolicyType string `json:"policyType,omitempty"`

	// Ingress is the list of ingress rules
	Ingress []IngressRule `json:"ingress,omitempty"`

	// Egress is the list of egress rules
	Egress []EgressRule `json:"egress,omitempty"`
}

// PolicyEndpointsStatus defines the observed state of PolicyEndpoints
type PolicyEndpointsStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// PolicyEndpoints is the Schema for the policyendpoints API
type PolicyEndpoints struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PolicyEndpointsSpec   `json:"spec,omitempty"`
	Status PolicyEndpointsStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// PolicyEndpointsList contains a list of PolicyEndpoints
type PolicyEndpointsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PolicyEndpoints `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PolicyEndpoints{}, &PolicyEndpointsList{})
}
