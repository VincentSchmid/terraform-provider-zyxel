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
  source_cidr            = "2001:db8:lan::/64"
  destination_cidr       = "2001:db8:server::/128"
  destination_port_start = 443
  destination_port_end   = 443
}

resource "zyxel_acl_rule" "restricted_client" {
  name             = "Restricted-Client-Example"
  action           = "reject"
  order            = 12
  direction        = "lan_to_wan"
  mac_address      = "AA:BB:CC:DD:EE:FF"
  source_cidr      = "192.0.2.0/24"
  destination_cidr = "198.51.100.10/32"
  protocol         = "tcp_udp"
  tcp_flag         = "syn"
}
