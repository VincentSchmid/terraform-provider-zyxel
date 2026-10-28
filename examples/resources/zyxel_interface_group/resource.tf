# Interface paths depend on your router. Obtain WAN IpIfacePath values from
# its WAN interface list and LAN IntfPath values from its LAN port list.
variable "wan_interface_paths" {
  description = "WAN IpIfacePath values selected from this router's UI."
  type        = set(string)
}

variable "lan_interface_paths" {
  description = "LAN IntfPath values selected from this router's UI."
  type        = set(string)
}

resource "zyxel_interface_group" "example" {
  name           = "Example"
  wan_interfaces = var.wan_interface_paths
  lan_interfaces = var.lan_interface_paths
}

# Addresses are documentation placeholders; substitute your actual LAN and pool.
resource "zyxel_lan" "example" {
  interface_group_id = zyxel_interface_group.example.id
  ip_address         = "198.51.100.1"
  subnet_mask        = "255.255.255.0"
  igmp_snooping      = "standard"
  dhcp = {
    mode                 = "server"
    beginning_ip_address = "198.51.100.100"
    ending_ip_address    = "198.51.100.200"
    auto_reserve_ip      = true
    dhcp_lease_time      = "1d"
  }
}
