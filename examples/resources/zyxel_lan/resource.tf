# Built-in Default group; no zyxel_interface_group resource is needed.
resource "zyxel_lan" "default" {
  interface_group_id   = "Default"
  ip_address           = "192.168.1.1"
  subnet_mask          = "255.255.255.0"
  igmp_snooping        = "standard"
  dhcp_mode            = "server"
  beginning_ip_address = "192.168.1.100"
  ending_ip_address    = "192.168.1.200"
  auto_reserve_ip      = true
}

# Alternatives (do not manage the same group with multiple resources):
#
# DHCP disabled:
#   dhcp_mode = "disabled"
#   Omit beginning_ip_address, ending_ip_address, and relay_server_address.
#   Omit auto_reserve_ip or set it to false.
#
# DHCP relay:
#   dhcp_mode            = "relay"
#   relay_server_address = "192.168.2.10"
#   Omit beginning_ip_address and ending_ip_address.
#   Omit auto_reserve_ip or set it to false.
