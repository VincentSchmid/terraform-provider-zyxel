# WARNING: ACL updates are non-atomic. Deny rules are temporarily removed,
# potentially allowing normally blocked traffic. Management rule changes may also
# interrupt router access. Use a maintenance window and ensure a recovery path is
# available.
# Choose ONE policy example per router; each resource owns the entire ACL tail.
# Destination addresses are documentation placeholders. Set the source ranges
# and management CIDRs for your network, and verify management port 443 applies.

# A custom service replaces the inline protocol and port filters. Each rule can
# reference its own service name or service_id; rules no longer have to share one
# scope.
resource "zyxel_service" "https" {
  name              = "policy-https"
  protocol          = "tcp"
  source_ports      = "*"
  destination_ports = "443"
}

# Management rules precede normal accepts, then every drop rule. At least one drop
# rule is required. Review unrelated prefix accepts for overlap before creating
# this tail policy. Do not manage generated rows individually.
resource "zyxel_acl_policy" "https" {
  management_rules = [{
    name              = "Management"
    action            = "accept"
    protocol          = "tcp"
    ip_version        = "ipv4"
    direction         = "lan_to_router"
    source_cidr       = "192.0.2.0/24"
    destination_cidr  = "192.0.2.1/32"
    destination_ports = "443"
  }]

  rules = [
    {
      action            = "accept"
      source_cidr       = "192.0.2.0/24"
      protocol          = "tcp"
      ip_version        = "ipv4"
      direction         = "wan_to_lan"
      destination_cidr  = "203.0.113.10/32"
      destination_ports = "443"
    },
    {
      action            = "accept"
      source_cidr       = "198.51.100.0/24"
      protocol          = "tcp"
      ip_version        = "ipv4"
      direction         = "wan_to_lan"
      destination_cidr  = "203.0.113.10/32"
      destination_ports = "443"
    },
  ]

  drop_rules = [{
    action            = "drop"
    source_cidr       = "0.0.0.0/0"
    protocol          = "tcp"
    ip_version        = "ipv4"
    direction         = "wan_to_lan"
    destination_cidr  = "203.0.113.10/32"
    destination_ports = "443"
  }]
}

resource "zyxel_acl_policy" "https_service" {
  management_rules = [{
    name              = "Management"
    action            = "accept"
    protocol          = "tcp"
    ip_version        = "ipv4"
    direction         = "lan_to_router"
    source_cidr       = "192.0.2.0/24"
    destination_cidr  = "192.0.2.1/32"
    destination_ports = "443"
  }]

  rules = [
    {
      action           = "accept"
      source_cidr      = "192.0.2.0/24"
      ip_version       = "ipv4"
      direction        = "wan_to_lan"
      destination_cidr = "203.0.113.10/32"
      service_id       = zyxel_service.https.id
    },
    {
      action           = "accept"
      source_cidr      = "198.51.100.0/24"
      ip_version       = "ipv4"
      direction        = "wan_to_lan"
      destination_cidr = "203.0.113.10/32"
      service_id       = zyxel_service.https.id
    },
  ]

  drop_rules = [{
    action           = "drop"
    source_cidr      = "0.0.0.0/0"
    ip_version       = "ipv4"
    direction        = "wan_to_lan"
    destination_cidr = "203.0.113.10/32"
    service_id       = zyxel_service.https.id
  }]
}

# Mixed-scope accepts are allowed; one or more drops follow them. The effective
# order is management, then normal accepts, then drops.
resource "zyxel_acl_policy" "mixed" {
  management_rules = [{
    name              = "Management"
    action            = "accept"
    protocol          = "tcp"
    ip_version        = "ipv4"
    direction         = "lan_to_router"
    source_cidr       = "192.0.2.0/24"
    destination_cidr  = "192.0.2.1/32"
    destination_ports = "443"
  }]

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
