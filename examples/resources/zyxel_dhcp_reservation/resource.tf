resource "zyxel_dhcp_reservation" "nas" {
  mac_address  = "02:00:00:00:00:20"
  ipv4_address = "192.168.1.20"
}
