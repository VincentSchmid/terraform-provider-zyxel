data "zyxel_cloudflare_ipv4_ranges" "cloudflare" {}

output "cloudflare_ipv4_ranges" {
  value = data.zyxel_cloudflare_ipv4_ranges.cloudflare.ranges
}
