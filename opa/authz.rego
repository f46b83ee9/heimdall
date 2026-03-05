# Heimdall Authorization Policy
#
# Input:
#   user_id: string
#   groups: []string
#   tenant_id: string
#   resource: string
#   action: string
#
# Output:
#   allow: bool
#   effective_filters: []string
#   accessible_tenants: []string

package proxy.authz

import rego.v1

# Default deny
default allow := false
default effective_filters := []
default accessible_tenants := []

# ─── Helper: subject matching ───

# Check if a policy subject matches the current user or any of their groups
subject_matches(subject) if {
    subject.type == "user"
    subject.id == input.user_id
}

subject_matches(subject) if {
    subject.type == "group"
    subject.id in input.groups
}

# ─── Helper: action matching ───

# Check if the requested action matches a policy action (supports wildcard)
action_matches(policy_action) if {
    policy_action == "*"
}

action_matches(policy_action) if {
    policy_action == input.action
}

# ─── Helper: tenant matching ───

# Expand tenant scope (supports wildcard via data.proxy.tenants)
tenant_in_scope(policy_scope) if {
    some t in policy_scope.tenants
    t == input.tenant_id
}

tenant_in_scope(policy_scope) if {
    some t in policy_scope.tenants
    t == "*"
    input.tenant_id in object.keys(data.proxy.tenants)
}

# ─── Matching policies ───

# Collect all matching ALLOW policies
matching_allow_policies contains policy if {
    some policy in data.proxy.policies
    policy.effect == "allow"
    some subject in policy.subjects
    subject_matches(subject)
    some action in policy.actions
    action_matches(action)
    tenant_in_scope(policy.scope)
}

# Collect all matching DENY policies
matching_deny_policies contains policy if {
    some policy in data.proxy.policies
    policy.effect == "deny"
    some subject in policy.subjects
    subject_matches(subject)
    some action in policy.actions
    action_matches(action)
    tenant_in_scope(policy.scope)
}

# ─── Authorization decision ───

# If ANY deny matches → deny (deny overrides allow)
allow if {
    count(matching_deny_policies) == 0
    count(matching_allow_policies) > 0
}

# ─── Effective filters ───

# Collect all filters from matching allow policies (union)
all_allow_filters contains f if {
    some policy in matching_allow_policies
    some f in policy.filters
}

# If ANY allow policy has empty filters → effective_filters = [] (full access)
has_empty_filter_policy if {
    some policy in matching_allow_policies
    count(policy.filters) == 0
}

# Effective filters: empty if any policy grants full access, otherwise union of all filters
effective_filters := [] if {
    allow
    has_empty_filter_policy
}

effective_filters := [f | some f in all_allow_filters] if {
    allow
    not has_empty_filter_policy
}

# ─── Accessible tenants ───

# Collect all accessible tenants from matching allow policies
accessible_tenant_set contains t if {
    count(matching_deny_policies) == 0
    some policy in data.proxy.policies
    policy.effect == "allow"
    some subject in policy.subjects
    subject_matches(subject)
    some action in policy.actions
    action_matches(action)
    some t_scope in policy.scope.tenants
    t_scope == "*"
    some t in object.keys(data.proxy.tenants)
}

accessible_tenant_set contains t if {
    count(matching_deny_policies) == 0
    some policy in data.proxy.policies
    policy.effect == "allow"
    some subject in policy.subjects
    subject_matches(subject)
    some action in policy.actions
    action_matches(action)
    some t in policy.scope.tenants
    t != "*"
}

accessible_tenants := [t | some t in accessible_tenant_set]
