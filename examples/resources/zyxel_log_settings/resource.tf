provider "zyxel" {}

# Record new events locally. Apply selects Local File mode, stopping remote forwarding.
resource "zyxel_log_settings" "router" {
  enabled = true
}
