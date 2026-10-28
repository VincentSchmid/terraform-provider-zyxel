resource "zyxel_dns_record" "nas" {
  hostname     = "nas.home.arpa"
  ipv4_address = "192.168.1.20"
}
