variable "https_source_ranges" {
  type    = set(string)
  default = ["198.51.100.0/24", "192.0.2.0/24"]
}

locals {
  https_filter = {
    protocol          = "tcp"
    ip_version        = "ipv4"
    direction         = "wan_to_lan"
    destination_cidr  = "203.0.113.10/32"
    destination_ports = "443"
  }
}

# Accepts are evaluated in list order, then every drop rule. At least one drop
# rule is required. Review unrelated prefix accepts for overlap before creating
# this tail policy. Do not manage generated rows individually.
resource "zyxel_acl_policy" "https" {
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
# order is the accept list, then the drop list.
resource "zyxel_acl_policy" "mixed" {
  rules = [
    {
      name              = "WebDAV"
      action            = "accept"
      protocol          = "tcp"
      ip_version        = "ipv4"
      direction         = "wan_to_lan"
      source_cidr       = "0.0.0.0/0"
      destination_cidr  = "203.0.113.20/32"
      destination_ports = "5006"
    },
    {
      name              = "VPN"
      action            = "accept"
      protocol          = "udp"
      ip_version        = "ipv4"
      direction         = "wan_to_lan"
      source_cidr       = "0.0.0.0/0"
      destination_cidr  = "203.0.113.20/32"
      destination_ports = "1194"
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
