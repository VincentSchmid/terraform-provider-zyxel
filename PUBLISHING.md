# Publishing this provider

The [Terraform Registry](https://registry.terraform.io) publishes any public
GitHub repository named `terraform-provider-<type>`. This repository is
`VincentSchmid/terraform-provider-zyxel`, so the provider address is
`VincentSchmid/zyxel` on `registry.terraform.io`.

## One-time setup

### 1. Create a signing key

The registry requires every released version to be GPG-signed with a key you
register. RSA works; the default ECC key type is rejected.

```sh
gpg --full-generate-key          # choose RSA, 4096 bits, no expiry (or rotate deliberately)
gpg --list-secret-keys --keyid-format=long
gpg --armor --export "<KEY_ID_OR_EMAIL>"
```

Keep the private key offline, and never commit it.

### 2. Add the key to the registry

Sign in to the [Terraform Registry](https://registry.terraform.io) with GitHub,
then go to **User Settings -> Signing Keys** and paste the ASCII-armored public
key. The registry will verify every release signature against it.

### 3. Add the GitHub Actions secrets

In the GitHub repository: **Settings -> Secrets and variables -> Actions**:

| Secret | Value |
| --- | --- |
| `GPG_PRIVATE_KEY` | `gpg --armor --export-secret-keys "<KEY_ID>"` |
| `PASSPHRASE` | The passphrase of that key |

`GITHUB_TOKEN` is provided by Actions; no personal token is needed.

### 4. Publish the provider once

In the registry, choose **Publish -> Provider**, select this GitHub repository,
and confirm. The registry creates a `release` webhook on the repository that
ingests future versions automatically. (If the webhook breaks, remove it and use
**Resync** on the provider settings page.)

## Releasing a version

1. Make sure `main` builds, tests pass, and the docs are regenerated.
2. Tag a semantic version and push it:

   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

   There must be no branch with the same name as the tag.

3. The `release` workflow runs GoReleaser, which builds every platform, writes
   `terraform-provider-zyxel_<version>_SHA256SUMS` plus its `.sig`, attaches
   `terraform-provider-zyxel_<version>_manifest.json`, and publishes the GitHub
   release. Nothing is left to click: `.goreleaser.yml` sets `release.draft:
   false`, and the registry only ingests finalized releases.
4. To check a release after the fact:

   ```sh
   gh release download v<version> -p '*SHA256SUMS*' -p '*manifest.json'
   gpg --verify terraform-provider-zyxel_<version>_SHA256SUMS.sig \
                terraform-provider-zyxel_<version>_SHA256SUMS
   ```

   The signature must come from the key registered with the registry.
5. Version `0.1.0` appears in the registry within a few minutes. Check it with:

   ```sh
   terraform init   # required_providers { zyxel = { source = "VincentSchmid/zyxel" } }
   ```

## What a release must contain

GoReleaser produces this layout automatically; it is listed so you can check a
release after it is published:

- `terraform-provider-zyxel_<version>_<os>_<arch>.zip` per platform, each
  containing a binary named `terraform-provider-zyxel_v<version>`
- `terraform-provider-zyxel_<version>_manifest.json` (from
  `terraform-registry-manifest.json`, which declares protocol `6.0` for the
  Plugin Framework)
- `terraform-provider-zyxel_<version>_SHA256SUMS` with a checksum for every zip
  and the manifest
- `terraform-provider-zyxel_<version>_SHA256SUMS.sig`, a binary (not armored)
  detached signature of the checksums made with the registered key

Platforms follow the recommended Terraform combinations: `linux`, `darwin`,
`windows`, and `freebsd` on `amd64`, `arm64`, `386`, and `arm` (except
`darwin/386`).

## When the registry reports a version problem

The registry rejects a release that is still a draft, is not signed with a
registered key, or lacks `terraform-provider-zyxel_<version>_manifest.json` as
an **asset**. `checksum.extra_files` only adds a file to `SHA256SUMS`; the asset
itself comes from `release.extra_files` in `.goreleaser.yml`. If a release is
wrong, delete the release and the tag and push the tag again at a fixed commit —
after the registry has ingested a version, always release a new version instead.

## Notes

- **Never replace a released version.** Users pin checksums, so a changed
  `v0.1.0` breaks them. Release a new version instead.
- **Tags are immutable in the registry.** Deleting the GitHub release does not
  remove the registry version.
- **Docs come from `docs/`.** `index.md` is the provider overview, and one page
  per resource and data source is required for a complete listing.
- **Alternative registries.** The [OpenTofu Registry](https://registry.opentofu.org)
  ingests the same GitHub releases automatically, so OpenTofu users can consume
  the provider without extra work.
- **Publishing is not applying.** Shipping a provider version does not touch any
  router; only `terraform apply` in a configuration does.
