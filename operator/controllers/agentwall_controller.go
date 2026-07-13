package controllers

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
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
//+kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete

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

	// ── ConfigMap reconciliation (existing behavior, unchanged) ────────────
	if err := r.reconcileConfigMap(ctx, &policy); err != nil {
		logger.Error(err, "Failed to reconcile ConfigMap")
		return ctrl.Result{}, err
	}

	// ── FR-5 §5.5.8: NetworkPolicy reconciliation (new) ────────────────────
	npName, err := r.reconcileNetworkPolicy(ctx, &policy)
	if err != nil {
		logger.Error(err, "Failed to reconcile NetworkPolicy")
		return ctrl.Result{}, err
	}

	// ── Status update ──────────────────────────────────────────────────────
	policy.Status.Phase = "Active"
	policy.Status.LastReconcileTime = time.Now().Format(time.RFC3339)
	policy.Status.NetworkPolicyName = npName
	if err := r.Status().Update(ctx, &policy); err != nil {
		logger.Error(err, "Failed to update AgentWallPolicy status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
}

// reconcileConfigMap ensures a ConfigMap named "<policy>-policy-config" exists
// in the policy's namespace with the desired policy YAML. This preserves the
// original controller behavior verbatim; only its packaging (extracted method)
// has changed.
func (r *AgentWallPolicyReconciler) reconcileConfigMap(ctx context.Context, policy *agentwallv1alpha1.AgentWallPolicy) error {
	logger := log.FromContext(ctx)

	cmName := policy.Name + "-policy-config"
	var cm corev1.ConfigMap
	err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: policy.Namespace}, &cm)
	switch {
	case errors.IsNotFound(err):
		cm = corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cmName,
				Namespace: policy.Namespace,
			},
			Data: map[string]string{
				"policy.yaml": policy.Spec.Policy,
			},
		}
		if err := ctrl.SetControllerReference(policy, &cm, r.Scheme); err != nil {
			return err
		}
		logger.Info("Creating a new ConfigMap", "ConfigMap.Namespace", cm.Namespace, "ConfigMap.Name", cm.Name)
		return r.Create(ctx, &cm)
	case err != nil:
		return err
	default:
		if cm.Data["policy.yaml"] != policy.Spec.Policy {
			cm.Data["policy.yaml"] = policy.Spec.Policy
			return r.Update(ctx, &cm)
		}
	}
	return nil
}

// reconcileNetworkPolicy implements FR-5 §5.5.8.
//
// Three cases:
//
//  1. Spec.NetworkPolicy.Enforced == false, no existing NP  -> nothing to do.
//  2. Spec.NetworkPolicy.Enforced == false, existing NP     -> delete it
//     (someone flipped enforcement OFF; we don't leave stale rules around).
//  3. Spec.NetworkPolicy.Enforced == true                   -> create or
//     update the NP so it matches buildNetworkPolicy(policy).
//
// Returns the NetworkPolicy name that should be reflected on Status. When
// enforcement is off, returns "" so the status field is cleared on next update.
func (r *AgentWallPolicyReconciler) reconcileNetworkPolicy(ctx context.Context, policy *agentwallv1alpha1.AgentWallPolicy) (string, error) {
	logger := log.FromContext(ctx)

	npName := networkPolicyName(policy.Name)
	npKey := types.NamespacedName{Name: npName, Namespace: policy.Namespace}

	var existing networkingv1.NetworkPolicy
	getErr := r.Get(ctx, npKey, &existing)

	// Case 1 & 2: enforcement is off.
	if !policy.Spec.NetworkPolicy.Enforced {
		if errors.IsNotFound(getErr) {
			return "", nil
		}
		if getErr != nil {
			return "", getErr
		}
		// Only delete resources we own — guards against name collisions with
		// an unrelated NetworkPolicy the user created by hand.
		if !isManagedByUs(&existing) {
			logger.Info("Skipping delete of NetworkPolicy not managed by operator",
				"NetworkPolicy.Namespace", existing.Namespace,
				"NetworkPolicy.Name", existing.Name)
			return "", nil
		}
		logger.Info("NetworkPolicy enforcement disabled; deleting existing NetworkPolicy",
			"NetworkPolicy.Namespace", existing.Namespace,
			"NetworkPolicy.Name", existing.Name)
		if err := r.Delete(ctx, &existing); err != nil && !errors.IsNotFound(err) {
			return "", err
		}
		return "", nil
	}

	// Case 3: enforcement is on. Build desired state and reconcile.
	desired := buildNetworkPolicy(policy)
	if err := ctrl.SetControllerReference(policy, desired, r.Scheme); err != nil {
		return "", err
	}

	if errors.IsNotFound(getErr) {
		logger.Info("Creating NetworkPolicy",
			"NetworkPolicy.Namespace", desired.Namespace,
			"NetworkPolicy.Name", desired.Name)
		if err := r.Create(ctx, desired); err != nil {
			return "", err
		}
		return desired.Name, nil
	}
	if getErr != nil {
		return "", getErr
	}

	// If a NetworkPolicy with our name exists but wasn't created by us, refuse
	// to overwrite it — surface a clear log line instead. This can happen if
	// the user pre-created a policy with the same name; adopting it silently
	// would violate least surprise.
	if !isManagedByUs(&existing) {
		logger.Info("NetworkPolicy exists but is not managed by operator; refusing to update",
			"NetworkPolicy.Namespace", existing.Namespace,
			"NetworkPolicy.Name", existing.Name)
		return existing.Name, nil
	}

	// apiequality.Semantic.DeepEqual handles pointer fields (Port/Protocol)
	// and defaulted zero values correctly — a plain reflect.DeepEqual would
	// spuriously report differences after server-side defaulting.
	if !apiequality.Semantic.DeepEqual(existing.Spec, desired.Spec) ||
		!apiequality.Semantic.DeepEqual(existing.Labels, desired.Labels) {
		existing.Spec = desired.Spec
		existing.Labels = desired.Labels
		logger.Info("Updating NetworkPolicy",
			"NetworkPolicy.Namespace", existing.Namespace,
			"NetworkPolicy.Name", existing.Name)
		if err := r.Update(ctx, &existing); err != nil {
			return "", err
		}
	}
	return existing.Name, nil
}

// isManagedByUs returns true if the object carries the operator's
// managed-by label. Prevents accidental takeover of pre-existing resources.
func isManagedByUs(obj metav1.Object) bool {
	return obj.GetLabels()[ManagedByLabelKey] == ManagedByLabelValue
}

// SetupWithManager sets up the controller with the Manager.
func (r *AgentWallPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&agentwallv1alpha1.AgentWallPolicy{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Complete(r)
}
