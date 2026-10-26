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

# Review unrelated prefix accepts for overlap before creating this tail policy.
# Do not create a separate catch-all drop or manage generated rows individually.
resource "zyxel_acl_policy" "https" {
  name = "HTTPS-Sources"
  rules = concat([
    for cidr in sort(tolist(var.https_source_ranges)) : merge(local.https_filter, {
      action      = "accept"
      source_cidr = cidr
    })
    ], [merge(local.https_filter, {
      action      = "drop"
      source_cidr = "0.0.0.0/0"
  })])
}

# A custom service replaces the inline protocol and port filters for every rule.
# The computed protocol is then "all" and the service selects protocol and ports.
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
  name = "HTTPS-Service-Sources"
  rules = concat([
    for cidr in sort(tolist(var.https_source_ranges)) : merge(local.service_filter, {
      action      = "accept"
      source_cidr = cidr
    })
    ], [merge(local.service_filter, {
      action      = "drop"
      source_cidr = "0.0.0.0/0"
  })])
}
