package cidr.window

import rego.v1

default allow := false
default reason := "denied: outside UTC change window without active incident grace extension"

# Permit off-window CIDR translation updates up to 15 minutes during active incident mitigation.
grace_permitted if {
	input.grace_extension.active == true
	count(input.grace_extension.incident_id) >= 4
	input.grace_extension.extra_minutes <= 15
	input.actor_role in {"net-architect", "incident-lead"}
}

allow if {
	grace_permitted
}

allow if {
	not grace_permitted
	input.actor_role in {"net-architect", "incident-lead", "ipam-bot"}
	input.utc_hour >= 1
	input.utc_hour <= 23
}

reason := "allowed via active incident grace extension" if {
	allow
	grace_permitted
}

reason := "allowed within UTC network change window" if {
	allow
	not grace_permitted
}
