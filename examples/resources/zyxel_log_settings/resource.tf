provider "zyxel" {}

# Record new events in the router's local log file.
resource "zyxel_log_settings" "router" {
  enabled = true
  mode    = "local"
}
