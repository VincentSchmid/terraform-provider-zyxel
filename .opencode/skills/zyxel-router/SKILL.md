---
name: Zyxel Router
description: Look up Zyxel router documentation, account permissions, LAN/WAN management access, logging, and firmware compatibility for this Terraform provider.
---

# Zyxel Router Documentation

Use these references for questions about supported Zyxel router series and the
permissions needed by this provider. Fetch the relevant source before answering;
do not treat this note as an API specification.

## Git Author Convention

For commits made by OpenCode in this repository, use author name `OpenCode` and
email `opencode.<current-model-name>@vincentschmid.xyz`. Substitute the active
model's name rather than reusing a previous model's identity. For example, with
GPT-6.1 Sol, use `opencode.gpt-6.1-sol@vincentschmid.xyz`.
Apply the identity only to this repository or the individual commit, not global
Git configuration. This convention does not authorize commits or pushes unless
the user requests them.

## Documentation Scope and Privacy

- This is a public provider repository. Keep deployment-specific router models,
  installed firmware versions, ISP details, addresses, account names and logging
  state in the deployment's private infrastructure repository, not this skill.
- Model names in documentation titles describe the manuals' coverage, not a
  user's installed hardware. Match documentation to the target model and
  firmware before claiming compatibility.
- Model-series manuals and newer series help are useful references, not proof
  of exact-build behavior or verified DAL API authorization.

## Documentation Links

1. Official Zyxel AX/DX/EX/PX-series help: User Account, including Group and
   Remote Privilege definitions:
   https://service-provider.zyxel.com/compact-help/AX-DX-EX-PX-Series/AX-DX-EX-PX_5-70/h_Maintenance_UserAccount_AddEdit.html
   This is 5.70-series help; it does not establish behavior on other builds.
2. EX5501-B0 / AX7501-B0 / PX7501-B0 User's Guide, chapter 32, page 290:
   https://www.manualslib.com/manual/1864676/Zyxel-Communications-Ex5501-B0.html?page=290
   Documents Administrator versus User privileges and administrator-only
   Network Setting and Security settings menus. The hosting page is titled
   EX5501-B0, but the manual explicitly covers AX7501-B0 too.
3. Same model-series guide, page 289, User Account Add/Edit:
   https://www.manualslib.com/manual/1864676/Zyxel-Communications-Ex5501-B0.html?page=289
4. Full model-series guide PDF, hosted by a third party:
   https://aselcom.com/Anexos%20PS/Manuales/EX5501-B0_User%27s_Guide_V5.pdf
5. Official series help for Maintenance > Log Setting:
   https://service-provider.zyxel.com/compact-help/AX-DX-EX-PX-Series/AX-DX-EX-PX_5-70/h_Maintenance_LogSetting.html
   Documents Syslog Logging, Local File versus Remote mode, and the Active Log
   categories for System Log and Security Log. Verify labels on the target
   firmware; this reference does not establish that logging is enabled.

## Account Permissions

- Group and Remote Privilege are separate controls. Group selects Administrator
  or User privileges; Remote Privilege selects the permitted management access
  side: LAN, WAN, or LAN/WAN.
- The official series help grants Administrator accounts all Web Configurator
  menus, including Home Networking, NAT, and Firewall. User accounts have
  Monitor and Maintenance menus, not those configuration areas.
- The documented account screen does not offer custom per-feature permissions
  or an API-only role. Do not claim that no firmware-specific alternative can
  exist; none was established by these references.
- Recommend a separate account, such as `terraform`, in the Administrator group
  with LAN-only access when Terraform connects from the LAN. The username does
  not need to be `admin`. Do not enable WAN management just to use the provider.
- This provider uses the web-interface API; SSH and Telnet are unnecessary.

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
