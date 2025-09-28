package policies

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"github.com/evergreenos/selfhost-backend/internal/config"
	generated "github.com/evergreenos/selfhost-backend/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Store captures the persistence operations required for policy management.
type Store interface {
	CreatePolicy(ctx context.Context, arg generated.CreatePolicyParams) (generated.Policy, error)
	GetPolicyByID(ctx context.Context, policyID string) (generated.Policy, error)
	GetLatestPolicyByTenant(ctx context.Context, tenantID pgtype.UUID) (generated.Policy, error)
	ListPoliciesByTenant(ctx context.Context, arg generated.ListPoliciesByTenantParams) ([]generated.Policy, error)
	UpdatePolicy(ctx context.Context, arg generated.UpdatePolicyParams) (generated.Policy, error)
	DeletePolicy(ctx context.Context, policyID string) error
}

// PolicyService implements policy management with digital signatures for backend use
type PolicyService struct {
	store        Store
	signingKey   ed25519.PrivateKey
	verifyingKey ed25519.PublicKey
	signingKeyID string
	now          func() time.Time
}

var errStoreRequired = errors.New("policy store is required")

// WithClock overrides the service clock for deterministic testing.
func (s *PolicyService) WithClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func loadSigningMaterial(cfg config.PolicyConfig) (ed25519.PrivateKey, ed25519.PublicKey, string, error) {
	if cfg.SigningKeyPath == "" {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
		}
		keyID := cfg.SigningKeyID
		if keyID == "" {
			keyID = fmt.Sprintf("policy-key-%d", time.Now().Unix())
		}
		return privateKey, publicKey, keyID, nil
	}

	raw, err := os.ReadFile(cfg.SigningKeyPath)
	if err != nil {
		return nil, nil, "", fmt.Errorf("read signing key: %w", err)
	}

	trimmed := strings.TrimSpace(string(raw))
	var keyBytes []byte
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		keyBytes = decoded
	} else if len(raw) == ed25519.PrivateKeySize {
		keyBytes = append([]byte(nil), raw...)
	} else {
		return nil, nil, "", fmt.Errorf("decode signing key: %w", err)
	}

	if len(keyBytes) != ed25519.PrivateKeySize {
		return nil, nil, "", fmt.Errorf("signing key must be %d bytes", ed25519.PrivateKeySize)
	}

	privateKey := ed25519.PrivateKey(append([]byte(nil), keyBytes...))
	publicKey := privateKey.Public().(ed25519.PublicKey)

	keyID := cfg.SigningKeyID
	if keyID == "" {
		sum := sha256.Sum256(publicKey)
		keyID = fmt.Sprintf("key-%x", sum[:4])
	}

	return privateKey, publicKey, keyID, nil
}

// NewPolicyService creates a new policy service with Ed25519 signing.
func NewPolicyService(store Store, cfg config.PolicyConfig) (*PolicyService, error) {
	privateKey, publicKey, keyID, err := loadSigningMaterial(cfg)
	if err != nil {
		return nil, err
	}

	return &PolicyService{
		store:        store,
		signingKey:   privateKey,
		verifyingKey: publicKey,
		signingKeyID: keyID,
		now:          time.Now,
	}, nil
}

// CreatePolicyBundle creates a new policy with digital signature
func (s *PolicyService) CreatePolicyBundle(ctx context.Context, tenantID pgtype.UUID, name string, policy *pb.PolicyBundle, createdBy string) (*pb.PolicyBundle, error) {
	if s.store == nil {
		return nil, errStoreRequired
	}
	// Validate inputs
	if policy == nil {
		return nil, fmt.Errorf("policy is required")
	}
	if name == "" {
		return nil, fmt.Errorf("policy name is required")
	}
	if createdBy == "" {
		return nil, fmt.Errorf("created by is required")
	}

	versionTime := s.now().UTC()
	if latest, err := s.store.GetLatestPolicyByTenant(ctx, tenantID); err == nil && latest.VersionTimestamp.Valid {
		if !versionTime.After(latest.VersionTimestamp.Time) {
			versionTime = latest.VersionTimestamp.Time.Add(time.Millisecond)
		}
	}

	policyID := fmt.Sprintf("policy-%d", versionTime.UnixNano())
	policy.Id = policyID
	policy.Name = name
	policy.Version = timestamppb.New(versionTime)
	policy.SigningKeyId = s.signingKeyID

	signature, err := s.signPolicy(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to sign policy: %w", err)
	}
	policy.Signature = signature

	policyJSON, err := s.policyToJSON(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize policy: %w", err)
	}

	creatorUUID, err := parseUUID(createdBy)
	if err != nil {
		return nil, fmt.Errorf("invalid created by: %w", err)
	}

	_, err = s.store.CreatePolicy(ctx, generated.CreatePolicyParams{
		PolicyID:         policyID,
		TenantID:         tenantID,
		Name:             name,
		PolicyBundle:     []byte(policyJSON),
		VersionTimestamp: pgtype.Timestamptz{Time: versionTime, Valid: true},
		Signature:        &signature,
		SigningKeyID:     &s.signingKeyID,
		CreatedBy:        uuidToPG(creatorUUID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store policy: %w", err)
	}

	return policy, nil
}

// GetPolicyByID retrieves a policy by ID with signature verification
func (s *PolicyService) GetPolicyByID(ctx context.Context, policyID string) (*pb.PolicyBundle, error) {
	if s.store == nil {
		return nil, errStoreRequired
	}
	if policyID == "" {
		return nil, fmt.Errorf("policy ID is required")
	}

	record, err := s.store.GetPolicyByID(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("policy not found: %w", err)
	}
	bundle, err := s.toBundle(record)
	if err != nil {
		return nil, err
	}
	if err := s.verifyPolicySignature(bundle); err != nil {
		return nil, fmt.Errorf("policy signature verification failed: %w", err)
	}
	return bundle, nil
}

// GetLatestPolicyByTenant retrieves the latest policy for a tenant
func (s *PolicyService) GetLatestPolicyByTenant(ctx context.Context, tenantID pgtype.UUID) (*pb.PolicyBundle, error) {
	if s.store == nil {
		return nil, errStoreRequired
	}
	record, err := s.store.GetLatestPolicyByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("no policy found for tenant: %w", err)
	}
	bundle, err := s.toBundle(record)
	if err != nil {
		return nil, err
	}
	if err := s.verifyPolicySignature(bundle); err != nil {
		return nil, fmt.Errorf("policy signature verification failed: %w", err)
	}
	return bundle, nil
}

// UpdatePolicyBundle updates an existing policy with new signature
func (s *PolicyService) UpdatePolicyBundle(ctx context.Context, policyID string, name string, policy *pb.PolicyBundle, updatedBy string) (*pb.PolicyBundle, error) {
	if s.store == nil {
		return nil, errStoreRequired
	}
	// Validate inputs
	if policy == nil {
		return nil, fmt.Errorf("policy is required")
	}
	if policyID == "" {
		return nil, fmt.Errorf("policy ID is required")
	}
	if updatedBy == "" {
		return nil, fmt.Errorf("updated by is required")
	}

	existing, err := s.store.GetPolicyByID(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("policy not found: %w", err)
	}

	if name == "" {
		name = existing.Name
	}

	versionTime := s.now().UTC()
	if existing.VersionTimestamp.Valid && !versionTime.After(existing.VersionTimestamp.Time) {
		versionTime = existing.VersionTimestamp.Time.Add(time.Millisecond)
	}

	policy.Id = policyID
	policy.Name = name
	policy.Version = timestamppb.New(versionTime)
	policy.SigningKeyId = s.signingKeyID

	signature, err := s.signPolicy(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to sign updated policy: %w", err)
	}
	policy.Signature = signature

	policyJSON, err := s.policyToJSON(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize updated policy: %w", err)
	}

	if _, err := s.store.UpdatePolicy(ctx, generated.UpdatePolicyParams{
		PolicyID:         policyID,
		Name:             policy.Name,
		PolicyBundle:     []byte(policyJSON),
		VersionTimestamp: pgtype.Timestamptz{Time: versionTime, Valid: true},
		Signature:        &signature,
		SigningKeyID:     &s.signingKeyID,
	}); err != nil {
		return nil, fmt.Errorf("failed to update policy: %w", err)
	}

	return policy, nil
}

// DeletePolicyBundle marks a policy as deleted
func (s *PolicyService) DeletePolicyBundle(ctx context.Context, policyID string, deletedBy string) error {
	if s.store == nil {
		return errStoreRequired
	}
	if policyID == "" {
		return fmt.Errorf("policy ID is required")
	}

	if err := s.store.DeletePolicy(ctx, policyID); err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	return nil
}

// ListPolicyBundles returns policies for the tenant ordered by version desc.
func (s *PolicyService) ListPolicyBundles(ctx context.Context, tenantID pgtype.UUID, limit, offset int32) ([]*pb.PolicyBundle, error) {
	if s.store == nil {
		return nil, errStoreRequired
	}
	if limit <= 0 {
		limit = 25
	}
	records, err := s.store.ListPoliciesByTenant(ctx, generated.ListPoliciesByTenantParams{
		TenantID: tenantID,
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	bundles := make([]*pb.PolicyBundle, 0, len(records))
	for _, record := range records {
		bundle, err := s.toBundle(record)
		if err != nil {
			return nil, err
		}
		if err := s.verifyPolicySignature(bundle); err != nil {
			return nil, fmt.Errorf("policy signature verification failed: %w", err)
		}
		bundles = append(bundles, bundle)
	}
	return bundles, nil
}

func parseUUID(value string) (uuid.UUID, error) {
	if strings.TrimSpace(value) == "" {
		return uuid.UUID{}, fmt.Errorf("uuid is required")
	}
	return uuid.Parse(value)
}

func uuidToPG(id uuid.UUID) pgtype.UUID {
	var out pgtype.UUID
	out.Valid = true
	copy(out.Bytes[:], id[:])
	return out
}

func (s *PolicyService) toBundle(record generated.Policy) (*pb.PolicyBundle, error) {
	bundle, err := s.jsonToPolicy(string(record.PolicyBundle))
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize policy: %w", err)
	}
	bundle.Id = record.PolicyID
	bundle.Name = record.Name
	if record.VersionTimestamp.Valid {
		bundle.Version = timestamppb.New(record.VersionTimestamp.Time)
	}
	if record.Signature != nil {
		bundle.Signature = *record.Signature
	}
	if record.SigningKeyID != nil {
		bundle.SigningKeyId = *record.SigningKeyID
	}
	return bundle, nil
}

// signPolicy creates an Ed25519 signature for the policy
func (s *PolicyService) signPolicy(policy *pb.PolicyBundle) (string, error) {
	// Create a copy of the policy without the signature for signing
	policyForSigning := &pb.PolicyBundle{
		Id:           policy.Id,
		Name:         policy.Name,
		Version:      policy.Version,
		Apps:         policy.Apps,
		Updates:      policy.Updates,
		Browser:      policy.Browser,
		Network:      policy.Network,
		Security:     policy.Security,
		SigningKeyId: policy.SigningKeyId,
		// Signature field is intentionally omitted
	}

	// Serialize policy to canonical JSON
	policyJSON, err := json.Marshal(policyForSigning)
	if err != nil {
		return "", fmt.Errorf("failed to marshal policy for signing: %w", err)
	}

	// Sign the JSON bytes
	signature := ed25519.Sign(s.signingKey, policyJSON)

	// Return base64 encoded signature
	return base64.StdEncoding.EncodeToString(signature), nil
}

// verifyPolicySignature verifies the Ed25519 signature of a policy
func (s *PolicyService) verifyPolicySignature(policy *pb.PolicyBundle) error {
	if policy.Signature == "" {
		return fmt.Errorf("policy signature is missing")
	}

	if policy.SigningKeyId != s.signingKeyID {
		return fmt.Errorf("policy signed with unknown key ID: %s", policy.SigningKeyId)
	}

	// Decode signature from base64
	signature, err := base64.StdEncoding.DecodeString(policy.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Create policy copy without signature for verification
	policyForVerification := &pb.PolicyBundle{
		Id:           policy.Id,
		Name:         policy.Name,
		Version:      policy.Version,
		Apps:         policy.Apps,
		Updates:      policy.Updates,
		Browser:      policy.Browser,
		Network:      policy.Network,
		Security:     policy.Security,
		SigningKeyId: policy.SigningKeyId,
	}

	// Serialize to canonical JSON
	policyJSON, err := json.Marshal(policyForVerification)
	if err != nil {
		return fmt.Errorf("failed to marshal policy for verification: %w", err)
	}

	// Verify signature
	if !ed25519.Verify(s.verifyingKey, policyJSON, signature) {
		return fmt.Errorf("policy signature verification failed")
	}

	return nil
}

// policyToJSON converts protobuf policy to JSON string
func (s *PolicyService) policyToJSON(policy *pb.PolicyBundle) (string, error) {
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal policy to JSON: %w", err)
	}
	return string(policyJSON), nil
}

// jsonToPolicy converts JSON string to protobuf policy
func (s *PolicyService) jsonToPolicy(policyJSON string) (*pb.PolicyBundle, error) {
	var policy pb.PolicyBundle
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy from JSON: %w", err)
	}
	return &policy, nil
}

// GetDefaultPolicy returns a default policy bundle
func (s *PolicyService) GetDefaultPolicy() *pb.PolicyBundle {
	return &pb.PolicyBundle{
		Id:      "default-policy",
		Name:    "Default Policy",
		Version: timestamppb.Now(),
		Apps: &pb.AppPolicy{
			AutoInstallRequired:   true,
			AutoRemoveForbidden:   true,
			InstallTimeoutSeconds: 300,
		},
		Updates: &pb.UpdatePolicy{
			Channel:     pb.UpdateChannel_UPDATE_CHANNEL_STABLE,
			AutoInstall: false,
			AutoReboot:  false,
		},
		Security: &pb.SecurityPolicy{
			SelinuxEnforcing:         true,
			RequireScreenLock:        true,
			ScreenLockTimeoutSeconds: 300,
			EnforceScreenLock:        true,
		},
		SigningKeyId: s.signingKeyID,
	}
}
