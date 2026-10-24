package provider

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
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const maxResponseBytes = 4 << 20

type Credentials struct {
	Username string
	Password string
}

func (Credentials) String() string   { return "Credentials{Username:[REDACTED], Password:[REDACTED]}" }
func (Credentials) GoString() string { return "Credentials{Username:[REDACTED], Password:[REDACTED]}" }

type Client struct {
	endpoint    string
	credentials Credentials
	httpClient  *http.Client
	sessionGate chan struct{}
}

func NewClient(endpoint string, credentials Credentials, timeout time.Duration) (*Client, error) {
	return &Client{
		endpoint: strings.TrimRight(endpoint, "/"), credentials: credentials,
		httpClient:  &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		sessionGate: make(chan struct{}, 1),
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

func (c *Client) ReadStatus(ctx context.Context) (map[string]any, error) {
	var status map[string]any
	err := c.withSession(ctx, func(s *routerSession) error {
		response, err := s.get(ctx, "/cgi-bin/DAL?oid=status&sessionkey="+url.QueryEscape(s.sessionKey))
		if err != nil {
			return err
		}
		value, err := s.decryptResponse(response)
		if err != nil {
			return err
		}
		if result, ok := value["result"].(string); ok && result != "ZCFG_SUCCESS" {
			return errors.New("router rejected the status request")
		}
		objects, ok := value["Object"].([]any)
		if !ok || len(objects) == 0 {
			return errors.New("router status response did not contain a status object")
		}
		status, ok = objects[0].(map[string]any)
		if !ok || len(status) == 0 {
			return errors.New("router status response contained an empty status object")
		}
		return nil
	})
	return status, err
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

type DHCPReservation struct {
	Index   int64
	MACAddr string
	IPAddr  string
	Enabled bool
}

func (c *Client) DHCPReservations(ctx context.Context) ([]DHCPReservation, error) {
	var reservations []DHCPReservation
	err := c.withSession(ctx, func(s *routerSession) error {
		var err error
		reservations, err = s.readDHCPReservations(ctx)
		return err
	})
	return reservations, err
}

func (c *Client) CreateDHCPReservation(ctx context.Context, mac, ip string, enabled bool) (bool, error) {
	if !enabled {
		return false, errors.New("DHCP reservations can only be created enabled")
	}
	created := false
	err := c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readDHCPReservations(ctx)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if sameDHCPMAC(row.MACAddr, mac) {
				return errors.New("a DHCP reservation for this MAC already exists; import it before managing it")
			}
		}
		result, err := s.writeDAL(ctx, http.MethodPost, "static_dhcp", "", map[string]any{
			"Enable": enabled, "MACAddr": mac, "IPAddr": ip, "BrWan": "Default",
		})
		if err != nil {
			var ambiguous *ambiguousWriteError
			if errors.As(err, &ambiguous) {
				created = true
			}
			return err
		}
		if result["result"] != "ZCFG_SUCCESS" {
			return errors.New("router rejected the DHCP reservation create request")
		}
		created = true
		rows, err = s.readDHCPReservations(ctx)
		if err != nil {
			return err
		}
		found, err := findDHCPReservation(rows, mac)
		if err != nil {
			return err
		}
		if found == nil || found.IPAddr != ip || found.Enabled != enabled {
			return errors.New("DHCP reservation create could not be confirmed by readback")
		}
		return nil
	})
	return created, err
}

func (c *Client) DeleteDHCPReservation(ctx context.Context, mac string) error {
	return c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readDHCPReservations(ctx)
		if err != nil {
			return err
		}
		found, err := findDHCPReservation(rows, mac)
		if err != nil {
			return err
		}
		if found == nil {
			return nil
		}
		if found.Index < 1 {
			return errors.New("router returned an invalid DHCP reservation index")
		}
		result, err := s.writeDAL(ctx, http.MethodDelete, "static_dhcp", fmt.Sprint(found.Index), map[string]any{})
		if err != nil {
			return err
		}
		if result["result"] != "ZCFG_SUCCESS" {
			return errors.New("router rejected the DHCP reservation delete request")
		}
		rows, err = s.readDHCPReservations(ctx)
		if err != nil {
			return err
		}
		remaining, err := findDHCPReservation(rows, mac)
		if err != nil {
			return err
		}
		if remaining != nil {
			return errors.New("DHCP reservation delete could not be confirmed by readback")
		}
		return nil
	})
}

func findDHCPReservation(rows []DHCPReservation, mac string) (*DHCPReservation, error) {
	var found *DHCPReservation
	for i := range rows {
		if sameDHCPMAC(rows[i].MACAddr, mac) {
			if found != nil {
				return nil, errors.New("router returned multiple DHCP reservations for this MAC")
			}
			found = &rows[i]
		}
	}
	return found, nil
}

func sameDHCPMAC(left, right string) bool {
	canonicalLeft, leftErr := normalizeImportMAC(left)
	canonicalRight, rightErr := normalizeImportMAC(right)
	return leftErr == nil && rightErr == nil && canonicalLeft == canonicalRight
}

func (s *routerSession) readDHCPReservations(ctx context.Context) ([]DHCPReservation, error) {
	response, err := s.get(ctx, "/cgi-bin/DAL?oid=static_dhcp&sessionkey="+url.QueryEscape(s.sessionKey))
	if err != nil {
		return nil, err
	}
	value, err := s.decryptResponse(response)
	if err != nil {
		return nil, err
	}
	if value["result"] != "ZCFG_SUCCESS" {
		return nil, errors.New("router rejected the DHCP reservation read request")
	}
	objects, ok := value["Object"].([]any)
	if !ok {
		return nil, errors.New("router DHCP response did not contain a reservation list")
	}
	rows := make([]DHCPReservation, 0, len(objects))
	for _, object := range objects {
		row, ok := object.(map[string]any)
		if !ok {
			return nil, errors.New("router returned a malformed DHCP reservation")
		}
		index, ok := integerValue(row["Index"])
		if !ok || index < 1 {
			return nil, errors.New("router returned an invalid DHCP reservation index")
		}
		mac, macOK := row["MACAddr"].(string)
		ip, ipOK := row["IPAddr"].(string)
		enabled, enabledOK := row["Enable"].(bool)
		if !macOK || !ipOK || !enabledOK {
			return nil, errors.New("router returned an incomplete DHCP reservation")
		}
		parsedIP, err := netip.ParseAddr(ip)
		if err != nil || !parsedIP.Is4() {
			return nil, errors.New("router returned a DHCP reservation with an invalid IPv4 address")
		}
		canonicalMAC, err := normalizeImportMAC(mac)
		if err != nil {
			return nil, errors.New("router returned an invalid DHCP reservation MAC address")
		}
		rows = append(rows, DHCPReservation{Index: index, MACAddr: canonicalMAC, IPAddr: ip, Enabled: enabled})
	}
	return rows, nil
}

func integerValue(value any) (int64, bool) {
	switch v := value.(type) {
	case float64:
		if v >= 1 && v == float64(int64(v)) {
			return int64(v), true
		}
	case json.Number:
		parsed, err := v.Int64()
		return parsed, err == nil && parsed >= 1
	case int64:
		return v, v >= 1
	case int:
		return int64(v), v >= 1
	}
	return 0, false
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
		return nil, &ambiguousWriteError{message: "router write request failed with an ambiguous outcome"}
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(content) > maxResponseBytes {
		return nil, &ambiguousWriteError{message: "router write response could not be read; outcome is ambiguous"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &responseStatusError{status: response.StatusCode}
	}
	result, err := s.decryptResponse(content)
	if err != nil {
		return nil, &ambiguousWriteError{message: "router write response could not be decoded; outcome is ambiguous"}
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
