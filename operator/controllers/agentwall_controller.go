package controllers

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	agentwallv1alpha1 "github.com/noviqtechnologies/agentwall/operator/api/v1alpha1"
)

// AgentWallPolicyReconciler reconciles a AgentWallPolicy object
type AgentWallPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=agentwall.io,resources=agentwallpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=agentwall.io,resources=agentwallpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete

func (r *AgentWallPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the AgentWallPolicy instance
	var policy agentwallv1alpha1.AgentWallPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("AgentWallPolicy resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get AgentWallPolicy")
		return ctrl.Result{}, err
	}

	// Create or Update ConfigMap for Policy
	cmName := policy.Name + "-policy-config"
	var cm corev1.ConfigMap
	err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: policy.Namespace}, &cm)
	if err != nil && errors.IsNotFound(err) {
		cm = corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cmName,
				Namespace: policy.Namespace,
			},
			Data: map[string]string{
				"policy.yaml": policy.Spec.Policy,
			},
		}
		if err := ctrl.SetControllerReference(&policy, &cm, r.Scheme); err != nil {
			return ctrl.Result{}, err
		}
		logger.Info("Creating a new ConfigMap", "ConfigMap.Namespace", cm.Namespace, "ConfigMap.Name", cm.Name)
		if err := r.Create(ctx, &cm); err != nil {
			return ctrl.Result{}, err
		}
	} else if err != nil {
		return ctrl.Result{}, err
	} else {
		// Update existing ConfigMap
		if cm.Data["policy.yaml"] != policy.Spec.Policy {
			cm.Data["policy.yaml"] = policy.Spec.Policy
			if err := r.Update(ctx, &cm); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	// Update Status
	policy.Status.Phase = "Active"
	policy.Status.LastReconcileTime = time.Now().Format(time.RFC3339)
	if err := r.Status().Update(ctx, &policy); err != nil {
		logger.Error(err, "Failed to update AgentWallPolicy status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AgentWallPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&agentwallv1alpha1.AgentWallPolicy{}).
		Owns(&corev1.ConfigMap{}).
		Complete(r)
}
