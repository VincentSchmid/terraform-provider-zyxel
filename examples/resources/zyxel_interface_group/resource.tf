# Interface paths depend on your router. Obtain WAN IpIfacePath values from
# its WAN interface list and LAN IntfPath values from its LAN port list.
resource "zyxel_interface_group" "example" {
  name           = "Example"
  wan_interfaces = ["IP.Interface.2"]
  lan_interfaces = ["Ethernet.Interface.2", "WiFi.SSID.3"]
}
