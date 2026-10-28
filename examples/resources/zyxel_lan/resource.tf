# Addresses are documentation placeholders; substitute your actual LAN and pool.
# Built-in Default group; no zyxel_interface_group resource is needed.
resource "zyxel_lan" "default" {
  interface_group_id = "Default"
  ip_address         = "192.0.2.1"
  subnet_mask        = "255.255.255.0"
  igmp_snooping      = "blocking"
  dns_mode           = "proxy"

  dhcp = {
    mode                 = "server"
    beginning_ip_address = "192.0.2.100"
    ending_ip_address    = "192.0.2.200"
    auto_reserve_ip      = false
    dhcp_lease_time      = "1d"
  }
}

# Alternatives (do not manage the same group with multiple resources):
#
# DHCP disabled:
#   dhcp = { mode = "disabled" }
#
# DHCP relay:
#   dhcp = {
#     mode                 = "relay"
#     relay_server_address = "198.51.100.10"
#   }
# In both alternatives omit dns_mode or use "proxy" (inactive).
