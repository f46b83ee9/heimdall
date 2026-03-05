package handler

// Action defines an authorization action evaluated against OPA.
type Action string

// Supported Heimdall proxy actions.
const (
	ActionRead        Action = "read"
	ActionWrite       Action = "write"
	ActionRulesRead   Action = "rules:read"
	ActionRulesWrite  Action = "rules:write"
	ActionAlertsRead  Action = "alerts:read"
	ActionAlertsWrite Action = "alerts:write" // reserved for future use
)
