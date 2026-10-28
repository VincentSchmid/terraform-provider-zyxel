# Replace the documentation address and locally administered MAC for your host.
resource "zyxel_dhcp_reservation" "host" {
  mac_address  = "02:00:00:00:00:20"
  ipv4_address = "192.0.2.20"
}
