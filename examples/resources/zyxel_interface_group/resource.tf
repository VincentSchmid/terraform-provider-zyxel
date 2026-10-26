# Interface paths depend on your router. Obtain WAN IpIfacePath values from
# its WAN interface list and LAN IntfPath values from its LAN port list.
resource "zyxel_interface_group" "guests" {
  name           = "Guests"
  wan_interfaces = ["IP.Interface.2"]
  lan_interfaces = ["Ethernet.Interface.2", "WiFi.SSID.3"]
}

resource "zyxel_lan" "guests" {
  interface_group_id = zyxel_interface_group.guests.id
  ip_address         = "192.168.20.1"
  subnet_mask        = "255.255.255.0"
  igmp_snooping      = "standard"
  dhcp = {
    mode                 = "server"
    beginning_ip_address = "192.168.20.100"
    ending_ip_address    = "192.168.20.200"
    auto_reserve_ip      = true
    dhcp_lease_time      = "1d"
  }
}
