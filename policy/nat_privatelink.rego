package cidr.resolution

import rego.v1

default allow := false
default reason := "denied: invalid resolution strategy or non-rfc1918 translated prefix"

allow if {
	input.strategy in {"nat_1to1", "privatelink_endpoint"}
	startswith(input.translated_cidr, "100.64.")
}

reason := "allowed: overlapping prefix resolved via NAT or PrivateLink" if {
	allow
}
