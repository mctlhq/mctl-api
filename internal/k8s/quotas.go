package k8s

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// QuotaClient fetches ResourceQuota usage from the Kubernetes API.
type QuotaClient struct {
	client kubernetes.Interface
}

// NewQuotaClient creates a QuotaClient using in-cluster config, falling back to KUBECONFIG.
func NewQuotaClient() (*QuotaClient, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		// Fallback to KUBECONFIG for local dev.
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{},
		).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("k8s quota client: %w", err)
		}
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s quota client: %w", err)
	}
	return &QuotaClient{client: cs}, nil
}

// GetNamespaceUsage returns the used and hard quota values from the first ResourceQuota in the namespace.
// Returns nil maps (not an error) if no ResourceQuota exists.
func (c *QuotaClient) GetNamespaceUsage(ctx context.Context, namespace string) (used, hard map[string]string, err error) {
	list, err := c.client.CoreV1().ResourceQuotas(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("listing resource quotas in %s: %w", namespace, err)
	}
	if len(list.Items) == 0 {
		return nil, nil, nil
	}
	q := list.Items[0]
	used = resourceListToStrings(q.Status.Used)
	hard = resourceListToStrings(q.Status.Hard)
	return used, hard, nil
}

func resourceListToStrings(rl corev1.ResourceList) map[string]string {
	out := make(map[string]string, len(rl))
	for name, qty := range rl {
		out[string(name)] = qty.String()
	}
	return out
}
