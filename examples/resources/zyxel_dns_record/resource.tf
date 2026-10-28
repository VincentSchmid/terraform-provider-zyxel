# Replace the reserved example.test name and documentation address for your host.
resource "zyxel_dns_record" "host" {
  hostname     = "host.example.test"
  ipv4_address = "192.0.2.20"
}
