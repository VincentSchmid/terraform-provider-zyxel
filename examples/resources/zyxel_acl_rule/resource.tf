# Addresses and MACs are documentation placeholders. Choose unused ACL positions
# after reviewing your router's complete rule table before applying.
resource "zyxel_service" "https" {
  name              = "HTTPS"
  description       = "Secure web"
  protocol          = "tcp"
  source_ports      = "*"
  destination_ports = "443"
}

resource "zyxel_acl_rule" "https" {
  name              = "Allow-HTTPS-Example"
  action            = "accept"
  order             = 10
  source_cidr       = "198.51.100.0/24"
  destination_cidr  = "192.0.2.10/32"
  source_ports      = "*"
  destination_ports = "443"
  packets_per_unit  = 100
  rate_limit_unit   = "minute"
}

resource "zyxel_acl_rule" "ipv6_https" {
  name                   = "Allow-IPv6-HTTPS-Example"
  action                 = "accept"
  order                  = 11
  ip_version             = "ipv6"
  direction              = "lan_to_wan"
  source_cidr            = "2001:db8:1::/64"
  destination_cidr       = "2001:db8:2::10/128"
  destination_port_start = 443
  destination_port_end   = 443
}

resource "zyxel_acl_rule" "restricted_client" {
  name             = "Restricted-Client-Example"
  action           = "reject"
  order            = 12
  direction        = "lan_to_wan"
  mac_address      = "02:00:00:00:00:20"
  source_cidr      = "192.0.2.0/24"
  destination_cidr = "198.51.100.10/32"
  protocol         = "tcp_udp"
  tcp_flag         = "syn"
}

# A custom service replaces inline protocol and port filters.
resource "zyxel_acl_rule" "https_service" {
  name             = "Allow-HTTPS-Service-Example"
  action           = "accept"
  order            = 13
  source_cidr      = "198.51.100.0/24"
  destination_cidr = "192.0.2.10/32"
  service_id       = zyxel_service.https.id
}
