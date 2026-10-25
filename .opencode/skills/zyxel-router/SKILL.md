---
name: Zyxel Router
description: Find user guides and online help for Zyxel routers relevant to this Terraform provider.
---

# Zyxel Router Documentation

Use these references as starting points for questions about the relevant Zyxel
router series. Find and fetch the section that matches the question before
answering; do not treat this note as an API specification.

## Documentation Scope and Privacy

- Model names in documentation titles describe the manuals' coverage, not a
  user's installed hardware. Match documentation to the target model and
  firmware before claiming compatibility.
- Model-series manuals and newer series help are useful references, not proof
  of exact-build behavior or verified DAL API authorization.

## Documentation Links

These references cover router setup, networking, security, monitoring and
maintenance. Use their table of contents or search to find the relevant topic.

1. Official Zyxel AX/DX/EX/PX-series online help:
   https://service-provider.zyxel.com/compact-help/AX-DX-EX-PX-Series/index.html
2. EX5501-B0 / AX7501-B0 / PX7501-B0 User's Guide on ManualsLib:
   https://www.manualslib.com/manual/1864676/Zyxel-Communications-Ex5501-B0.html
   The hosting page is titled EX5501-B0, but the guide covers all three models.
3. Full model-series User's Guide PDF, hosted by a third party:
   https://aselcom.com/Anexos%20PS/Manuales/EX5501-B0_User%27s_Guide_V5.pdf

## Provider Cross-Checks

Read the current implementation before claiming required API operations:

- `internal/provider/client.go`: login/session handling, status reads, and
  `static_dhcp` reads, creates, and deletes.
- `internal/provider/nat_client.go`: `nat` reads, creates, and deletes.
- `internal/provider/acl_client.go`: `firewall_acl` reads, creates, and deletes.
- `README.md`: current resource replacement behavior and hardware verification
  status.

The provider does not enforce a particular username or check the account group;
the router enforces authorization. Administrator + LAN is the documentation-backed
recommendation for configuration, not a verified per-endpoint permission matrix.
A successful login or status read does not prove write access. Check current
project warnings before suggesting live write tests, and never change a router
configuration without the user's authorization.
