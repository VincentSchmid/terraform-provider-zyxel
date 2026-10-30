resource "zyxel_service" "https" {
  name              = "HTTPS"
  description       = "Secure web"
  protocol          = "tcp"
  source_ports      = "*"
  destination_ports = "443"
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
