package operator

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	agentwallv1alpha1 "github.com/noviqtechnologies/agentwall/operator/api/v1alpha1"
	"github.com/noviqtechnologies/agentwall/operator/controllers"
)

func TestAgentWallPolicyReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = agentwallv1alpha1.AddToScheme(scheme)

	policy := &agentwallv1alpha1.AgentWallPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: agentwallv1alpha1.AgentWallPolicySpec{
			GatewayImage: "agentwall:test",
			Policy:       "default_action: deny\n",
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build()

	r := &controllers.AgentWallPolicyReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	ctx := context.TODO()
	req := ctrl.Request{
		NamespacedName: client.ObjectKey{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	_, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var cm corev1.ConfigMap
	err = fakeClient.Get(ctx, client.ObjectKey{Name: "test-policy-policy-config", Namespace: "default"}, &cm)
	if err != nil {
		t.Fatalf("failed to get configmap: %v", err)
	}

	if cm.Data["policy.yaml"] != "default_action: deny\n" {
		t.Errorf("expected policy data, got %v", cm.Data["policy.yaml"])
	}

	err = fakeClient.Get(ctx, client.ObjectKey{Name: "test-policy", Namespace: "default"}, policy)
	if err != nil {
		t.Fatalf("failed to get updated policy: %v", err)
	}

	if policy.Status.Phase != "Active" {
		t.Errorf("expected Active phase, got %v", policy.Status.Phase)
	}
}
