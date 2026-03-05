# Comprehensive Rego tests for Heimdall authorization policy
package proxy.authz_test

import rego.v1

import data.proxy.authz

# ─── Mock data ───

mock_tenants := {
    "acme": {"id": "acme", "name": "Acme Corp"},
    "globex": {"id": "globex", "name": "Globex Inc"},
}

mock_policies_allow_read := [{
    "id": 1,
    "name": "allow-alice-read",
    "effect": "allow",
    "subjects": [{"type": "user", "id": "alice"}],
    "actions": ["read"],
    "scope": {"tenants": ["acme"], "resources": ["metrics"]},
    "filters": ["env=\"prod\""],
}]

mock_policies_deny_overrides := [
    {
        "id": 1,
        "name": "allow-alice-read",
        "effect": "allow",
        "subjects": [{"type": "user", "id": "alice"}],
        "actions": ["read"],
        "scope": {"tenants": ["acme"], "resources": ["metrics"]},
        "filters": ["env=\"prod\""],
    },
    {
        "id": 2,
        "name": "deny-alice-read",
        "effect": "deny",
        "subjects": [{"type": "user", "id": "alice"}],
        "actions": ["read"],
        "scope": {"tenants": ["acme"], "resources": ["metrics"]},
        "filters": [],
    },
]

mock_policies_group := [{
    "id": 1,
    "name": "allow-devs-read",
    "effect": "allow",
    "subjects": [{"type": "group", "id": "developers"}],
    "actions": ["read"],
    "scope": {"tenants": ["acme"], "resources": ["metrics"]},
    "filters": ["namespace=\"prod\""],
}]

mock_policies_wildcard_tenant := [{
    "id": 1,
    "name": "allow-admin-all",
    "effect": "allow",
    "subjects": [{"type": "user", "id": "admin"}],
    "actions": ["*"],
    "scope": {"tenants": ["*"], "resources": ["metrics"]},
    "filters": [],
}]

mock_policies_empty_filters := [{
    "id": 1,
    "name": "allow-alice-full-access",
    "effect": "allow",
    "subjects": [{"type": "user", "id": "alice"}],
    "actions": ["read"],
    "scope": {"tenants": ["acme"], "resources": ["metrics"]},
    "filters": [],
}]

mock_policies_filter_union := [
    {
        "id": 1,
        "name": "allow-alice-prod",
        "effect": "allow",
        "subjects": [{"type": "user", "id": "alice"}],
        "actions": ["read"],
        "scope": {"tenants": ["acme"], "resources": ["metrics"]},
        "filters": ["env=\"prod\""],
    },
    {
        "id": 2,
        "name": "allow-alice-staging",
        "effect": "allow",
        "subjects": [{"type": "user", "id": "alice"}],
        "actions": ["read"],
        "scope": {"tenants": ["acme"], "resources": ["metrics"]},
        "filters": ["env=\"staging\""],
    },
]

# ─── Test: Basic allow ───

test_allow_user if {
    authz.allow with input as {
        "user_id": "alice",
        "groups": [],
        "tenant_id": "acme",
        "resource": "metrics",
        "action": "read",
    }
        with data.proxy.tenants as mock_tenants
        with data.proxy.policies as mock_policies_allow_read
}

# ─── Test: Deny when no matching policy ───

test_deny_no_matching_policy if {
    not authz.allow with input as {
        "user_id": "bob",
        "groups": [],
        "tenant_id": "acme",
        "resource": "metrics",
        "action": "read",
    }
        with data.proxy.tenants as mock_tenants
        with data.proxy.policies as mock_policies_allow_read
}

# ─── Test: Deny overrides allow ───

test_deny_overrides_allow if {
    not authz.allow with input as {
        "user_id": "alice",
        "groups": [],
        "tenant_id": "acme",
        "resource": "metrics",
        "action": "read",
    }
        with data.proxy.tenants as mock_tenants
        with data.proxy.policies as mock_policies_deny_overrides
}

# ─── Test: Group-based access ───

test_allow_group if {
    authz.allow with input as {
        "user_id": "bob",
        "groups": ["developers"],
        "tenant_id": "acme",
        "resource": "metrics",
        "action": "read",
    }
        with data.proxy.tenants as mock_tenants
        with data.proxy.policies as mock_policies_group
}

# ─── Test: Wildcard tenant expansion ───

test_wildcard_tenant if {
    authz.allow with input as {
        "user_id": "admin",
        "groups": [],
        "tenant_id": "acme",
        "resource": "metrics",
        "action": "read",
    }
        with data.proxy.tenants as mock_tenants
        with data.proxy.policies as mock_policies_wildcard_tenant
}

test_wildcard_tenant_globex if {
    authz.allow with input as {
        "user_id": "admin",
        "groups": [],
        "tenant_id": "globex",
        "resource": "metrics",
        "action": "write",
    }
        with data.proxy.tenants as mock_tenants
        with data.proxy.policies as mock_policies_wildcard_tenant
}

# ─── Test: Wildcard tenant does NOT match unregistered tenant ───

test_wildcard_tenant_unregistered if {
    not authz.allow with input as {
        "user_id": "admin",
        "groups": [],
        "tenant_id": "unknown-tenant",
        "resource": "metrics",
        "action": "read",
    }
        with data.proxy.tenants as mock_tenants
        with data.proxy.policies as mock_policies_wildcard_tenant
}

# ─── Test: Effective filters ───

test_effective_filters if {
    filters := authz.effective_filters with input as {
        "user_id": "alice",
        "groups": [],
        "tenant_id": "acme",
        "resource": "metrics",
        "action": "read",
    }
        with data.proxy.tenants as mock_tenants
        with data.proxy.policies as mock_policies_allow_read
    filters == ["env=\"prod\""]
}

# ─── Test: Empty filters (full access) ───

test_empty_filters_full_access if {
    filters := authz.effective_filters with input as {
        "user_id": "alice",
        "groups": [],
        "tenant_id": "acme",
        "resource": "metrics",
        "action": "read",
    }
        with data.proxy.tenants as mock_tenants
        with data.proxy.policies as mock_policies_empty_filters
    filters == []
}

# ─── Test: Filter union ───

test_filter_union if {
    filters := authz.effective_filters with input as {
        "user_id": "alice",
        "groups": [],
        "tenant_id": "acme",
        "resource": "metrics",
        "action": "read",
    }
        with data.proxy.tenants as mock_tenants
        with data.proxy.policies as mock_policies_filter_union
    count(filters) == 2
}

# ─── Test: Accessible tenants ───

test_accessible_tenants_wildcard if {
    tenants := authz.accessible_tenants with input as {
        "user_id": "admin",
        "groups": [],
        "tenant_id": "acme",
        "resource": "metrics",
        "action": "read",
    }
        with data.proxy.tenants as mock_tenants
        with data.proxy.policies as mock_policies_wildcard_tenant
    count(tenants) == 2
}

# ─── Test: Wrong action denied ───

test_deny_wrong_action if {
    not authz.allow with input as {
        "user_id": "alice",
        "groups": [],
        "tenant_id": "acme",
        "resource": "metrics",
        "action": "write",
    }
        with data.proxy.tenants as mock_tenants
        with data.proxy.policies as mock_policies_allow_read
}

# ─── Test: Wrong tenant denied ───

test_deny_wrong_tenant if {
    not authz.allow with input as {
        "user_id": "alice",
        "groups": [],
        "tenant_id": "globex",
        "resource": "metrics",
        "action": "read",
    }
        with data.proxy.tenants as mock_tenants
        with data.proxy.policies as mock_policies_allow_read
}
