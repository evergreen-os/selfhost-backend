package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Manager provides token issuance, validation, and credential helpers for EvergreenOS services.
type Manager struct {
	secret       []byte
	adminExpiry  time.Duration
	deviceExpiry time.Duration
	now          func() time.Time
	bcryptCost   int
}

// AdminClaims represents parsed admin JWT claims.
type AdminClaims struct {
	Subject   string
	TenantID  string
	Role      string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// DeviceClaims represents parsed device JWT claims.
type DeviceClaims struct {
	DeviceID  string
	TenantID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// NewManager constructs a Manager with the provided secret and expiry windows.
func NewManager(secret []byte, adminExpiry, deviceExpiry time.Duration) (*Manager, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("jwt secret must be at least 32 bytes")
	}
	if adminExpiry <= 0 || deviceExpiry <= 0 {
		return nil, fmt.Errorf("token expiries must be positive")
	}

	mgr := &Manager{
		secret:       append([]byte(nil), secret...),
		adminExpiry:  adminExpiry,
		deviceExpiry: deviceExpiry,
		now:          time.Now,
		bcryptCost:   bcrypt.DefaultCost,
	}
	return mgr, nil
}

// WithClock overrides the internal clock for deterministic testing.
func (m *Manager) WithClock(now func() time.Time) {
	if now != nil {
		m.now = now
	}
}

// WithBcryptCost overrides bcrypt cost factor for testing.
func (m *Manager) WithBcryptCost(cost int) {
	if cost >= bcrypt.MinCost {
		m.bcryptCost = cost
	}
}

type adminTokenClaims struct {
	Subject   string `json:"sub"`
	TenantID  string `json:"tenant_id"`
	Role      string `json:"role"`
	TokenType string `json:"token_type"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

type deviceTokenClaims struct {
	Subject   string `json:"sub"`
	TenantID  string `json:"tenant_id"`
	TokenType string `json:"token_type"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

var (
	errInvalidSignature = errors.New("invalid token signature")
	errTokenExpired     = errors.New("token expired")
	errWrongTokenType   = errors.New("unexpected token type")
)

// IssueAdminToken creates a signed JWT for an admin user.
func (m *Manager) IssueAdminToken(userID, tenantID, role string) (string, error) {
	if userID == "" {
		return "", fmt.Errorf("user id is required")
	}
	if tenantID == "" {
		return "", fmt.Errorf("tenant id is required")
	}
	if role == "" {
		return "", fmt.Errorf("role is required")
	}

	now := m.now().UTC()
	claims := adminTokenClaims{
		Subject:   userID,
		TenantID:  tenantID,
		Role:      role,
		TokenType: "admin",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(m.adminExpiry).Unix(),
	}
	return m.sign(claims)
}

// ParseAdminToken validates and returns admin claims from a JWT.
func (m *Manager) ParseAdminToken(token string) (*AdminClaims, error) {
	var claims adminTokenClaims
	if err := m.verify(token, &claims); err != nil {
		return nil, err
	}
	if claims.TokenType != "admin" {
		return nil, errWrongTokenType
	}
	if err := m.ensureNotExpired(claims.ExpiresAt); err != nil {
		return nil, err
	}
	return &AdminClaims{
		Subject:   claims.Subject,
		TenantID:  claims.TenantID,
		Role:      claims.Role,
		IssuedAt:  time.Unix(claims.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
	}, nil
}

// IssueDeviceToken creates a signed device token along with its bcrypt hash for storage.
func (m *Manager) IssueDeviceToken(deviceID, tenantID string) (token string, hashed string, err error) {
	if deviceID == "" {
		return "", "", fmt.Errorf("device id is required")
	}
	if tenantID == "" {
		return "", "", fmt.Errorf("tenant id is required")
	}

	now := m.now().UTC()
	claims := deviceTokenClaims{
		Subject:   deviceID,
		TenantID:  tenantID,
		TokenType: "device",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(m.deviceExpiry).Unix(),
	}

	token, err = m.sign(claims)
	if err != nil {
		return "", "", err
	}
	hashedBytes, err := bcrypt.GenerateFromPassword(m.bcryptDigest(token), m.bcryptCost)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash device token: %w", err)
	}
	return token, string(hashedBytes), nil
}

// VerifyDeviceToken ensures the provided token matches the stored hash and validates claims.
func (m *Manager) VerifyDeviceToken(token, deviceID, tenantID, hashed string) (*DeviceClaims, error) {
	if err := bcrypt.CompareHashAndPassword([]byte(hashed), m.bcryptDigest(token)); err != nil {
		return nil, fmt.Errorf("device token hash mismatch: %w", err)
	}

	var claims deviceTokenClaims
	if err := m.verify(token, &claims); err != nil {
		return nil, err
	}
	if claims.TokenType != "device" {
		return nil, errWrongTokenType
	}
	if claims.Subject != deviceID {
		return nil, fmt.Errorf("token subject mismatch")
	}
	if claims.TenantID != tenantID {
		return nil, fmt.Errorf("token tenant mismatch")
	}
	if err := m.ensureNotExpired(claims.ExpiresAt); err != nil {
		return nil, err
	}

	return &DeviceClaims{
		DeviceID:  claims.Subject,
		TenantID:  claims.TenantID,
		IssuedAt:  time.Unix(claims.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
	}, nil
}

// HashPassword hashes a plaintext password for storage.
func (m *Manager) HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password is required")
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), m.bcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashed), nil
}

// CheckPassword verifies a password against a bcrypt hash.
func (m *Manager) CheckPassword(password, hashed string) error {
	if hashed == "" {
		return fmt.Errorf("stored hash is empty")
	}
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
}

func (m *Manager) bcryptDigest(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func (m *Manager) sign(claims interface{}) (string, error) {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := encodedHeader + "." + encodedPayload
	signature := m.computeHMAC([]byte(signingInput))
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + encodedSignature, nil
}

func (m *Manager) verify(token string, claims interface{}) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("token format invalid")
	}
	signingInput := strings.Join(parts[:2], ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	expectedSig := m.computeHMAC([]byte(signingInput))
	if !hmac.Equal(signature, expectedSig) {
		return errInvalidSignature
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, claims); err != nil {
		return fmt.Errorf("decode claims: %w", err)
	}
	return nil
}

func (m *Manager) computeHMAC(data []byte) []byte {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write(data)
	return mac.Sum(nil)
}

func (m *Manager) ensureNotExpired(exp int64) error {
	now := m.now().UTC().Unix()
	if now > exp {
		return errTokenExpired
	}
	return nil
}

// GenerateRandomSecret produces a cryptographically strong secret suitable for JWT signing.
func GenerateRandomSecret(length int) ([]byte, error) {
	if length < 32 {
		return nil, fmt.Errorf("secret length must be at least 32 bytes")
	}
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("failed to read random bytes: %w", err)
	}
	return buf, nil
}

// DeriveTokenFingerprint produces a deterministic fingerprint for audit logging without revealing the token.
func DeriveTokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
