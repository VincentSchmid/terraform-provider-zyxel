package zyxel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxResponseBytes = 4 << 20

// Credentials contains router login credentials and redacts formatted output.
type Credentials struct {
	Username string
	Password string
}

func (Credentials) String() string   { return "Credentials{Username:[REDACTED], Password:[REDACTED]}" }
func (Credentials) GoString() string { return "Credentials{Username:[REDACTED], Password:[REDACTED]}" }

// Client serializes authenticated router operations. Construct it with NewClient;
// its zero value is not usable. Clients for the same normalized endpoint share
// a process-local lock. Other processes and endpoint aliases are not coordinated.
type Client struct {
	endpoint    string
	credentials Credentials
	httpClient  *http.Client
	sessionGate chan struct{}
}

var endpointSessionGates sync.Map

// NewClient configures a client without contacting the router. Each operation
// authenticates its own serialized session and performs best-effort logout.
func NewClient(endpoint string, credentials Credentials, timeout time.Duration) (*Client, error) {
	endpoint, err := NormalizeEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		return nil, errors.New("timeout must be positive")
	}
	endpoint = strings.TrimRight(endpoint, "/")
	gate, _ := endpointSessionGates.LoadOrStore(endpoint, make(chan struct{}, 1))
	return &Client{
		endpoint: endpoint, credentials: credentials,
		httpClient:  &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		sessionGate: gate.(chan struct{}),
	}, nil
}

type encryptedPayload struct {
	Content string `json:"content"`
	Key     string `json:"key,omitempty"`
	IV      string `json:"iv"`
}

type routerSession struct {
	client     *Client
	httpClient *http.Client
	key        []byte
	sessionKey string
}

// withSession serializes a router session across login, DAL operations, and logout.
func (c *Client) withSession(ctx context.Context, fn func(*routerSession) error) error {
	select {
	case c.sessionGate <- struct{}{}:
		defer func() { <-c.sessionGate }()
	case <-ctx.Done():
		return errors.New("router operation canceled")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return errors.New("unable to initialize router session")
	}
	httpClient := *c.httpClient
	httpClient.Jar = jar
	s := &routerSession{client: c, httpClient: &httpClient}
	if err := s.login(ctx); err != nil {
		return err
	}
	defer s.logout()
	return fn(s)
}

func (s *routerSession) writeDAL(ctx context.Context, method, oid, index string, data map[string]any) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.New("router write canceled before request")
	}
	plain, err := json.Marshal(data)
	if err != nil {
		return nil, errors.New("unable to prepare router write")
	}
	iv := make([]byte, 32)
	if _, err := rand.Read(iv); err != nil {
		return nil, errors.New("unable to prepare router write")
	}
	ciphertext, err := encryptCBC(s.key, iv[:aes.BlockSize], plain)
	if err != nil {
		return nil, errors.New("unable to prepare router write")
	}
	body, err := json.Marshal(encryptedPayload{Content: base64.StdEncoding.EncodeToString(ciphertext), IV: base64.StdEncoding.EncodeToString(iv)})
	if err != nil {
		return nil, errors.New("unable to prepare router write")
	}
	path := "/cgi-bin/DAL?oid=" + url.QueryEscape(oid) + "&sessionkey=" + url.QueryEscape(s.sessionKey)
	if method == http.MethodDelete {
		path += "&Index=" + url.QueryEscape(index)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.client.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("router write request could not be prepared")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("CSRFToken", s.sessionKey)
	req.Header.Set("If-Modified-Since", "Thu, 01 Jun 1970 00:00:00 GMT")
	response, err := s.httpClient.Do(req)
	if err != nil {
		return nil, &AmbiguousWriteError{message: "router write request failed with an ambiguous outcome"}
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(content) > maxResponseBytes {
		return nil, &AmbiguousWriteError{message: "router write response could not be read; outcome is ambiguous"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &responseStatusError{status: response.StatusCode}
	}
	result, err := s.decryptResponse(content)
	if err != nil {
		return nil, &AmbiguousWriteError{message: "router write response could not be decoded; outcome is ambiguous"}
	}
	if rotated, ok := result["sessionkey"].(string); ok && rotated != "" {
		s.sessionKey = rotated
	}
	return result, nil
}

func (s *routerSession) login(ctx context.Context) error {
	if _, err := s.get(ctx, "/GetInfoNoLogin"); err != nil {
		return errors.New("unable to start router session")
	}
	response, err := s.get(ctx, "/getRSAPublickKey")
	if err != nil {
		return errors.New("unable to retrieve router login key")
	}
	var publicKeyResponse struct {
		PublicKey string `json:"RSAPublicKey"`
	}
	if err := json.Unmarshal(response, &publicKeyResponse); err != nil || publicKeyResponse.PublicKey == "" {
		return errors.New("router returned an invalid login key response")
	}
	block, _ := pem.Decode([]byte(publicKeyResponse.PublicKey))
	if block == nil {
		return errors.New("router returned an invalid login key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if pkcs1, pkcs1Err := x509.ParsePKCS1PublicKey(block.Bytes); pkcs1Err == nil {
			parsed = pkcs1
		} else {
			return errors.New("router returned an invalid login key")
		}
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return errors.New("router returned an unsupported login key")
	}

	s.key = make([]byte, 32)
	iv := make([]byte, 32)
	if _, err := rand.Read(s.key); err != nil {
		return errors.New("unable to prepare router login")
	}
	if _, err := rand.Read(iv); err != nil {
		return errors.New("unable to prepare router login")
	}
	password := base64.StdEncoding.EncodeToString([]byte(s.client.credentials.Password))
	loginParams := map[string]any{"Input_Account": s.client.credentials.Username, "Input_Passwd": password, "currLang": "en", "RememberPassword": 0}
	plain, _ := json.Marshal(loginParams)
	ciphertext, err := encryptCBC(s.key, iv[:aes.BlockSize], plain)
	if err != nil {
		return errors.New("unable to prepare router login")
	}
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(base64.StdEncoding.EncodeToString(s.key)))
	if err != nil {
		return errors.New("unable to prepare router login")
	}
	body, _ := json.Marshal(encryptedPayload{Content: base64.StdEncoding.EncodeToString(ciphertext), Key: base64.StdEncoding.EncodeToString(encryptedKey), IV: base64.StdEncoding.EncodeToString(iv)})
	response, err = s.request(ctx, http.MethodPost, "/UserLogin", body, "application/json")
	if err != nil {
		return errors.New("router login request failed")
	}
	result, err := s.decryptResponse(response)
	if err != nil {
		return errors.New("router rejected login or returned an invalid login response")
	}
	if result["result"] != "ZCFG_SUCCESS" {
		return errors.New("router rejected login")
	}
	s.sessionKey, ok = result["sessionkey"].(string)
	if !ok || s.sessionKey == "" {
		return errors.New("router login response did not include a session key")
	}
	return nil
}

func (s *routerSession) logout() {
	if s.sessionKey == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = s.get(ctx, "/cgi-bin/UserLogout?sessionkey="+url.QueryEscape(s.sessionKey))
}

func (s *routerSession) get(ctx context.Context, path string) ([]byte, error) {
	return s.request(ctx, http.MethodGet, path, nil, "")
}

func (s *routerSession) request(ctx context.Context, method, path string, body []byte, contentType string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.client.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("router %s request could not be prepared", strings.ToLower(method))
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			return nil, errors.New("router request canceled")
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("router request timed out")
		}
		return nil, fmt.Errorf("router %s request failed", strings.ToLower(method))
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("router %s response could not be read", strings.ToLower(method))
	}
	if len(response) > maxResponseBytes {
		return nil, errors.New("router response exceeded size limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("router returned HTTP status %d", resp.StatusCode)
	}
	return response, nil
}

func (s *routerSession) decryptResponse(data []byte) (map[string]any, error) {
	var payload encryptedPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, errors.New("router returned invalid JSON")
	}
	if payload.Content == "" || payload.IV == "" {
		return nil, errors.New("router response was not encrypted")
	}
	iv, err := base64.StdEncoding.DecodeString(payload.IV)
	if err != nil || len(iv) < aes.BlockSize {
		return nil, errors.New("router response contained an invalid IV")
	}
	content, err := base64.StdEncoding.DecodeString(payload.Content)
	if err != nil || len(content) == 0 || len(content)%aes.BlockSize != 0 {
		return nil, errors.New("router response contained invalid ciphertext")
	}
	plain, err := decryptCBC(s.key, iv[:aes.BlockSize], content)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(plain, &result); err != nil {
		return nil, errors.New("router response contained invalid plaintext")
	}
	return result, nil
}

func encryptCBC(key, iv, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(append([]byte(nil), plain...), bytes.Repeat([]byte{byte(padding)}, padding)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(padded, padded)
	return padded, nil
}

func decryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("router response could not be decrypted")
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	padding := int(plain[len(plain)-1])
	if padding < 1 || padding > aes.BlockSize || padding > len(plain) {
		return nil, errors.New("router response contained invalid padding")
	}
	for _, b := range plain[len(plain)-padding:] {
		if int(b) != padding {
			return nil, errors.New("router response contained invalid padding")
		}
	}
	return plain[:len(plain)-padding], nil
}

type responseStatusError struct{ status int }

func (e *responseStatusError) Error() string {
	return fmt.Sprintf("router returned HTTP status %d", e.status)
}

// AmbiguousWriteError means a write may have reached the router. Callers must
// reconcile by natural identity rather than blindly retrying the write.
type AmbiguousWriteError struct{ message string }

func (e *AmbiguousWriteError) Error() string { return e.message }

// NormalizeEndpoint accepts a hostname, IP address, or HTTP(S) origin.
func NormalizeEndpoint(host string) (string, error) {
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
