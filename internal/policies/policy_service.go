package policies

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/evergreenos/selfhost-backend/internal/db"
	generated "github.com/evergreenos/selfhost-backend/internal/db/generated"
	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PolicyService implements policy management with digital signatures for backend use
type PolicyService struct {
	db            *db.DB
	signingKey    ed25519.PrivateKey
	verifyingKey  ed25519.PublicKey
	signingKeyID  string
}

// NewPolicyService creates a new policy service with Ed25519 signing
func NewPolicyService(database *db.DB) (*PolicyService, error) {
	// Generate Ed25519 key pair for policy signing
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	// Generate a key ID for the signing key
	keyID := fmt.Sprintf("policy-key-%d", time.Now().Unix())

	return &PolicyService{
		db:           database,
		signingKey:   privateKey,
		verifyingKey: publicKey,
		signingKeyID: keyID,
	}, nil
}

// CreatePolicyBundle creates a new policy with digital signature
func (s *PolicyService) CreatePolicyBundle(ctx context.Context, tenantID pgtype.UUID, name string, policy *pb.PolicyBundle, createdBy string) (*pb.PolicyBundle, error) {
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

	// Generate policy ID
	policyID := fmt.Sprintf("policy-%d", time.Now().UnixNano())

	// Set policy metadata
	policy.Id = policyID
	policy.Name = name
	policy.Version = timestamppb.Now()
	policy.SigningKeyId = s.signingKeyID

	// Sign the policy
	signature, err := s.signPolicy(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to sign policy: %w", err)
	}
	policy.Signature = signature

	// Convert policy to JSON for database storage
	policyJSON, err := s.policyToJSON(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize policy: %w", err)
	}

	// Store policy in database
	_, err = s.db.Queries().CreatePolicy(ctx, generated.CreatePolicyParams{
		PolicyID:         policyID,
		TenantID:         tenantID,
		Name:             name,
		PolicyBundle:     []byte(policyJSON),
		VersionTimestamp: pgtype.Timestamptz{Time: policy.Version.AsTime(), Valid: true},
		Signature:        &signature,
		SigningKeyID:     &s.signingKeyID,
		CreatedBy:        pgtype.UUID{Bytes: [16]byte{}, Valid: false}, // TODO: Convert createdBy string to UUID
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store policy: %w", err)
	}

	return policy, nil
}

// GetPolicyByID retrieves a policy by ID with signature verification
func (s *PolicyService) GetPolicyByID(ctx context.Context, policyID string) (*pb.PolicyBundle, error) {
	if policyID == "" {
		return nil, fmt.Errorf("policy ID is required")
	}

	// Retrieve policy from database
	policy, err := s.db.Queries().GetPolicyByID(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("policy not found: %w", err)
	}

	// Convert database policy to protobuf
	policyBundle, err := s.jsonToPolicy(string(policy.PolicyBundle))
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize policy: %w", err)
	}

	// Verify policy signature
	if err := s.verifyPolicySignature(policyBundle); err != nil {
		return nil, fmt.Errorf("policy signature verification failed: %w", err)
	}

	return policyBundle, nil
}

// GetLatestPolicyByTenant retrieves the latest policy for a tenant
func (s *PolicyService) GetLatestPolicyByTenant(ctx context.Context, tenantID pgtype.UUID) (*pb.PolicyBundle, error) {
	// Retrieve latest policy from database
	policy, err := s.db.Queries().GetLatestPolicyByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("no policy found for tenant: %w", err)
	}

	// Convert database policy to protobuf
	policyBundle, err := s.jsonToPolicy(string(policy.PolicyBundle))
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize policy: %w", err)
	}

	// Verify policy signature
	if err := s.verifyPolicySignature(policyBundle); err != nil {
		return nil, fmt.Errorf("policy signature verification failed: %w", err)
	}

	return policyBundle, nil
}

// UpdatePolicyBundle updates an existing policy with new signature
func (s *PolicyService) UpdatePolicyBundle(ctx context.Context, policyID string, name string, policy *pb.PolicyBundle, updatedBy string) (*pb.PolicyBundle, error) {
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

	// Update policy metadata
	policy.Id = policyID
	if name != "" {
		policy.Name = name
	}
	policy.Version = timestamppb.Now()
	policy.SigningKeyId = s.signingKeyID

	// Sign the updated policy
	signature, err := s.signPolicy(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to sign updated policy: %w", err)
	}
	policy.Signature = signature

	// Convert policy to JSON
	policyJSON, err := s.policyToJSON(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize updated policy: %w", err)
	}

	// Update policy in database
	_, err = s.db.Queries().UpdatePolicy(ctx, generated.UpdatePolicyParams{
		PolicyID:         policyID,
		Name:             policy.Name,
		PolicyBundle:     []byte(policyJSON),
		VersionTimestamp: pgtype.Timestamptz{Time: policy.Version.AsTime(), Valid: true},
		Signature:        &signature,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update policy: %w", err)
	}

	return policy, nil
}

// DeletePolicyBundle marks a policy as deleted
func (s *PolicyService) DeletePolicyBundle(ctx context.Context, policyID string, deletedBy string) error {
	if policyID == "" {
		return fmt.Errorf("policy ID is required")
	}

	// Hard delete policy in database (since we don't have soft delete fields)
	err := s.db.Queries().DeletePolicy(ctx, policyID)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	return nil
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