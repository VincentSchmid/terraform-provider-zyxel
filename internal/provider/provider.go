package provider

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	providerschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = &ZyxelProvider{}

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &ZyxelProvider{version: version} }
}

type ZyxelProvider struct{ version string }

type providerModel struct {
	Host           types.String `tfsdk:"host"`
	Username       types.String `tfsdk:"username"`
	Password       types.String `tfsdk:"password"`
	TimeoutSeconds types.Int64  `tfsdk:"timeout_seconds"`
}

func (p *ZyxelProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "zyxel"
	resp.Version = p.version
}

func (p *ZyxelProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = providerschema.Schema{Attributes: map[string]providerschema.Attribute{
		"host":            providerschema.StringAttribute{Optional: true, MarkdownDescription: "Router hostname, IP address, or `http(s)://` URL. Defaults to `ZYXEL_HOST` and uses HTTP when no scheme is given."},
		"username":        providerschema.StringAttribute{Optional: true, Sensitive: true, MarkdownDescription: "Router administrator username. May be set with `ZYXEL_USER`; provider configuration takes precedence."},
		"password":        providerschema.StringAttribute{Optional: true, Sensitive: true, MarkdownDescription: "Router administrator password. May be set with `ZYXEL_PASS`; provider configuration takes precedence."},
		"timeout_seconds": providerschema.Int64Attribute{Optional: true, MarkdownDescription: "HTTP timeout in seconds for each router request. Defaults to 10 seconds."},
	}}
}

func (p *ZyxelProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	for _, name := range unknownSettings(config) {
		detail := "This provider setting must be known during planning. Set it directly or use its documented environment variable."
		if name == "timeout_seconds" {
			detail = "timeout_seconds must be known during planning."
		}
		resp.Diagnostics.AddAttributeError(path.Root(name), "Unknown "+name, detail)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	host := resolve(config.Host, "ZYXEL_HOST")
	username, password := resolveCredentials(config.Username, config.Password)
	for _, issue := range validateConnectionSettings(host, username, password) {
		if issue.attribute != "" {
			resp.Diagnostics.AddAttributeError(path.Root(issue.attribute), issue.summary, issue.detail)
		} else {
			resp.Diagnostics.AddError(issue.summary, issue.detail)
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint, err := normalizeHost(host)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("host"), "Invalid router host", err.Error())
		return
	}
	timeout := int64(10)
	if !config.TimeoutSeconds.IsNull() {
		timeout = config.TimeoutSeconds.ValueInt64()
	}
	if timeout < 1 || timeout > 120 {
		resp.Diagnostics.AddAttributeError(path.Root("timeout_seconds"), "Invalid timeout_seconds", "timeout_seconds must be between 1 and 120.")
		return
	}

	client, err := NewClient(endpoint, Credentials{Username: username, Password: password}, time.Duration(timeout)*time.Second)
	if err != nil {
		resp.Diagnostics.AddError("Unable to configure Zyxel client", "The HTTP client could not be initialized.")
		return
	}
	resp.DataSourceData = client
	resp.ResourceData = client
}

type connectionIssue struct{ attribute, summary, detail string }

func validateConnectionSettings(host, username, password string) []connectionIssue {
	var issues []connectionIssue
	if host == "" {
		issues = append(issues, connectionIssue{attribute: "host", summary: "Missing router host", detail: "Set host in the provider configuration or ZYXEL_HOST in the environment."})
	}
	if (username == "") != (password == "") {
		detail := "Set username and password together. The provider checks static configuration first, then `ZYXEL_USER` and `ZYXEL_PASS`; it does not combine a partial pair across sources."
		issues = append(issues, connectionIssue{summary: "Incomplete router credentials", detail: detail})
	}
	if username == "" && password == "" {
		detail := "No complete credentials were found. Set both username and password in the provider configuration, or set both ZYXEL_USER and ZYXEL_PASS in the environment."
		issues = append(issues, connectionIssue{summary: "Missing router credentials", detail: detail})
	}
	return issues
}

func unknownSettings(config providerModel) []string {
	var unknown []string
	for name, attr := range map[string]types.String{"host": config.Host, "username": config.Username, "password": config.Password} {
		if attr.IsUnknown() {
			unknown = append(unknown, name)
		}
	}
	if config.TimeoutSeconds.IsUnknown() {
		unknown = append(unknown, "timeout_seconds")
	}
	return unknown
}

func (p *ZyxelProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewDHCPReservationResource, NewNATRuleResource, NewACLRuleResource, NewFirewallResource}
}
func (p *ZyxelProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{NewStatusDataSource, NewCloudflareIPv4RangesDataSource}
}

func resolve(config types.String, envName string) string {
	if !config.IsNull() {
		return strings.TrimSpace(config.ValueString())
	}
	return strings.TrimSpace(os.Getenv(envName))
}

func resolveCredentials(username, password types.String) (string, string) {
	configuredUsername, configuredPassword := !username.IsNull(), !password.IsNull()
	if configuredUsername && configuredPassword {
		return strings.TrimSpace(username.ValueString()), password.ValueString()
	}
	envUsername, envPassword := strings.TrimSpace(os.Getenv("ZYXEL_USER")), os.Getenv("ZYXEL_PASS")
	if envUsername != "" && envPassword != "" {
		return envUsername, envPassword
	}
	if configuredUsername || configuredPassword {
		if configuredUsername {
			return strings.TrimSpace(username.ValueString()), ""
		}
		return "", password.ValueString()
	}
	return envUsername, envPassword
}

func normalizeHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("host cannot be empty")
	}
	if !strings.Contains(host, "://") {
		host = "http://" + host
	}
	parsed, err := url.Parse(host)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") || strings.ContainsAny(parsed.Host, " \t\r\n") {
		return "", fmt.Errorf("host must be a hostname, IP address, or an HTTP(S) origin without credentials, a non-root path, query, or fragment")
	}
	if port := parsed.Port(); port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", fmt.Errorf("host contains an invalid port")
		}
	}
	if strings.HasSuffix(parsed.Host, ":") || strings.Contains(parsed.Host, "%") {
		return "", fmt.Errorf("host contains an invalid hostname or port")
	}
	if net.ParseIP(parsed.Hostname()) == nil && strings.Contains(parsed.Hostname(), "_") {
		return "", fmt.Errorf("host contains an invalid hostname")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}
