resource "zyxel_firewall" "router" {
  ipv4_enabled           = true
  ipv6_enabled           = true
  security_level         = "medium"
  dos_protection_enabled = true
}
