resource "zyxel_nat_rule" "https" {
  name                = "HTTPS-to-server"
  protocol            = "tcp"
  external_port_start = 443
  external_port_end   = 443
  internal_client     = "192.168.1.20"
  internal_port_start = 443
  internal_port_end   = 443
}
