package utils

import "strings"

func GetPodIdentifier(podName, podNamespace string) (string, error) {
	tmpName := strings.Split(podName, "-")
	replicaSetName := strings.Join(tmpName[:len(tmpName)-1], "-")

	return replicaSetName + "-" + podNamespace, nil
}

func GetPolicyEndpointIdentifier(name, namespace string) string {
	return name + namespace
}
