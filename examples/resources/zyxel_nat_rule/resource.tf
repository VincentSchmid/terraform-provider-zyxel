# Replace the documentation address with your server's LAN address.
resource "zyxel_nat_rule" "https" {
  name              = "HTTPS-to-server"
  protocol          = "tcp"
  external_ports    = "443"
  internal_client   = "192.0.2.20"
  translation_ports = "443"
}
