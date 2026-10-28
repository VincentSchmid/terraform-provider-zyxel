# WARNING: ACL updates are non-atomic. Deny rules are temporarily removed,
# potentially allowing normally blocked traffic. Management rule changes may also
# interrupt router access. Use a maintenance window and ensure a recovery path is
# available.
# Choose ONE policy example per router; each resource owns the entire ACL tail.
# Destination addresses are documentation placeholders. Set the source ranges
# and management CIDRs for your network, and verify management port 443 applies.

variable "https_source_ranges" {
  description = "Reviewed source CIDRs allowed to reach the HTTPS host."
  type        = set(string)
}

variable "management_source_cidr" {
  description = "Trusted administrator network that must retain router access."
  type        = string
}

variable "router_management_cidr" {
  description = "Router management IPv4 address with a /32 prefix."
  type        = string
}

locals {
  management_rules = [{
    name              = "Management"
    action            = "accept"
    protocol          = "tcp"
    ip_version        = "ipv4"
    direction         = "lan_to_router"
    source_cidr       = var.management_source_cidr
    destination_cidr  = var.router_management_cidr
    destination_ports = "443"
  }]
  https_filter = {
    protocol          = "tcp"
    ip_version        = "ipv4"
    direction         = "wan_to_lan"
    destination_cidr  = "203.0.113.10/32"
    destination_ports = "443"
  }
}

# Management rules precede normal accepts, then every drop rule. At least one drop
# rule is required. Review unrelated prefix accepts for overlap before creating
# this tail policy. Do not manage generated rows individually.
resource "zyxel_acl_policy" "https" {
  management_rules = local.management_rules

  rules = [
    for cidr in sort(tolist(var.https_source_ranges)) : merge(local.https_filter, {
      action      = "accept"
      source_cidr = cidr
    })
  ]

  drop_rules = [merge(local.https_filter, {
    action      = "drop"
    source_cidr = "0.0.0.0/0"
  })]
}

# A custom service replaces the inline protocol and port filters. Each rule can
# reference its own service name or service_id; rules no longer have to share one
# scope.
resource "zyxel_service" "https" {
  name              = "policy-https"
  protocol          = "tcp"
  source_ports      = "*"
  destination_ports = "443"
}

locals {
  service_filter = {
    ip_version       = "ipv4"
    direction        = "wan_to_lan"
    destination_cidr = "203.0.113.10/32"
    service_id       = zyxel_service.https.id
  }
}

resource "zyxel_acl_policy" "https_service" {
  management_rules = local.management_rules

  rules = [
    for cidr in sort(tolist(var.https_source_ranges)) : merge(local.service_filter, {
      action      = "accept"
      source_cidr = cidr
    })
  ]

  drop_rules = [merge(local.service_filter, {
    action      = "drop"
    source_cidr = "0.0.0.0/0"
  })]
}

# Mixed-scope accepts are allowed; one or more drops follow them. The effective
# order is management, then normal accepts, then drops.
resource "zyxel_acl_policy" "mixed" {
  management_rules = local.management_rules

  rules = [
    {
      name              = "Web"
      action            = "accept"
      protocol          = "tcp"
      ip_version        = "ipv4"
      direction         = "wan_to_lan"
      source_cidr       = "198.51.100.0/24"
      destination_cidr  = "203.0.113.20/32"
      destination_ports = "8443"
    },
    {
      name              = "DNS"
      action            = "accept"
      protocol          = "udp"
      ip_version        = "ipv4"
      direction         = "wan_to_lan"
      source_cidr       = "198.51.100.0/24"
      destination_cidr  = "203.0.113.20/32"
      destination_ports = "53"
    },
  ]

  drop_rules = [
    {
      name             = "Deny"
      action           = "drop"
      protocol         = "all"
      ip_version       = "ipv4"
      direction        = "wan_to_lan"
      source_cidr      = "0.0.0.0/0"
      destination_cidr = "0.0.0.0/0"
    },
  ]
}
