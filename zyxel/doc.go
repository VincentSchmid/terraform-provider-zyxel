// Package zyxel provides a Terraform-independent client for the supported Zyxel
// router DAL operations. It uses only the Go standard library.
//
// Each client serializes complete authenticated sessions. Mutations resolve
// current router indexes from natural identities and verify writes by readback.
// This protects operations within one client, not against other processes or
// concurrent changes through the router's web UI.
//
// Create operations can return both an error and an outcome indicating that a
// write succeeded or may have succeeded. Callers must preserve the natural
// identity and reconcile the router before retrying. Delete is idempotent for
// absent identities and refuses ambiguous duplicate matches.
package zyxel
