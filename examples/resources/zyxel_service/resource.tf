# Addresses are documentation placeholders. Choose an unused ACL position after
# reviewing your router's complete rule table before applying.
resource "zyxel_service" "https" {
  name              = "HTTPS"
  description       = "Secure web"
  protocol          = "tcp"
  source_ports      = "*"
  destination_ports = "443"
}

resource "zyxel_acl_rule" "https" {
  name             = "Allow-HTTPS"
  action           = "accept"
  order            = 10
  source_cidr      = "198.51.100.0/24"
  destination_cidr = "192.0.2.10/32"
  service_id       = zyxel_service.https.id
}

resource "zyxel_service" "ping" {
  name      = "Ping"
  protocol  = "icmp"
  icmp_type = 8
}

resource "zyxel_service" "ping6" {
  name        = "Ping6"
  protocol    = "icmpv6"
  icmpv6_type = 128
}

resource "zyxel_service" "gre" {
  name            = "GRE"
  protocol        = "other"
  protocol_number = 47
}
