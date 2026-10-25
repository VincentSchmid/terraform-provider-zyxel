resource "zyxel_acl_rule" "https" {
  name                   = "Allow-HTTPS-Example"
  action                 = "accept"
  order                  = 10
  source_cidr            = "198.51.100.0/24"
  destination_cidr       = "192.0.2.10/32"
  destination_port_start = 443
  destination_port_end   = 443
  packets_per_unit       = 100
  rate_limit_unit        = "minute"
}
