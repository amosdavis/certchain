package k8s

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// NewInClusterClient creates a Kubernetes client using the pod's mounted
// service-account credentials.  This is the standard client for certd when
// it runs inside a Kubernetes cluster.  Returns an error if the process is
// not running in-cluster (e.g. during local development without --k8s-enabled).
func NewInClusterClient() (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}
