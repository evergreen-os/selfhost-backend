package evergreenv1

import "google.golang.org/protobuf/types/known/timestamppb"

// UnimplementedDeviceServiceServer can be embedded for forward compatibility.
type UnimplementedDeviceServiceServer struct{}

// EnrollDeviceRequest represents a device enrollment request.
type EnrollDeviceRequest struct {
	EnrollmentToken  string
	EnrollmentSecret string
	Hardware         *HardwareInfo
	OsInfo           *OSInfo
	Network          *NetworkInfo
	AgentVersion     *Version
	Nonce            string
}

// HardwareInfo captures hardware details for enrollment.
type HardwareInfo struct {
	Model             string
	Manufacturer      string
	SerialNumber      string
	Architecture      Architecture
	TotalMemoryBytes  int64
	TotalStorageBytes int64
	TpmEnabled        bool
	TpmVersion        string
}

// Architecture enumerates supported hardware architectures.
type Architecture int32

const (
	Architecture_ARCHITECTURE_UNSPECIFIED Architecture = 0
	Architecture_ARCHITECTURE_X86_64      Architecture = 1
	Architecture_ARCHITECTURE_ARM64       Architecture = 2
	Architecture_ARCHITECTURE_AMD64       Architecture = 3
)

// String returns the textual representation for tests and logging.
func (a Architecture) String() string {
	switch a {
	case Architecture_ARCHITECTURE_X86_64:
		return "x86_64"
	case Architecture_ARCHITECTURE_ARM64:
		return "arm64"
	case Architecture_ARCHITECTURE_AMD64:
		return "amd64"
	default:
		return "unknown"
	}
}

// OSInfo captures EvergreenOS version details.
type OSInfo struct {
	Name          string
	Version       string
	KernelVersion string
	BuildId       string
}

// NetworkInfo describes the device network configuration used during enrollment.
type NetworkInfo struct {
	Hostname          string
	PrimaryMacAddress string
	Interfaces        []*NetworkInterface
}

// NetworkInterface describes a network interface on the device.
type NetworkInterface struct {
	Name       string
	MacAddress string
	Active     bool
	Type       string
}

// Version holds version metadata for the EvergreenOS agent.
type Version struct {
	Version   string
	Commit    string
	BuildTime *timestamppb.Timestamp
}

// EnrollDeviceResponse is returned after successful device enrollment.
type EnrollDeviceResponse struct {
	DeviceId               string
	DeviceToken            string
	PolicyBundle           *PolicyBundle
	ServerTime             *timestamppb.Timestamp
	CorrelationId          string
	CheckinIntervalSeconds int32
	PolicyEndpoint         string
	StateEndpoint          string
	EventsEndpoint         string
}

// PullPolicyRequest represents the policy pull RPC from a device.
type PullPolicyRequest struct {
	DeviceId             string
	DeviceToken          string
	CurrentPolicyVersion *timestamppb.Timestamp
	RequestTime          *timestamppb.Timestamp
}

// PullPolicyResponse is returned when the device requests the latest policy.
type PullPolicyResponse struct {
	PolicyBundle  *PolicyBundle
	PolicyUpdated bool
	ServerTime    *timestamppb.Timestamp
	NextCheckin   *timestamppb.Timestamp
	CorrelationId string
}

// ReportStateRequest contains a device state report payload.
type ReportStateRequest struct {
	DeviceId    string
	DeviceToken string
	State       *DeviceState
}

// ReportStateResponse contains the server evaluation of device state.
type ReportStateResponse struct {
	ServerTime                *timestamppb.Timestamp
	CorrelationId             string
	ShouldPullPolicy          bool
	NextReportIntervalSeconds int32
}

// Device represents a managed device entry.
type Device struct {
	DeviceId     string
	TenantId     string
	SerialNumber string
}

// EventType enumerates event categories.
type EventType int32

const (
	EventType_EVENT_TYPE_UNSPECIFIED EventType = 0
	EventType_EVENT_TYPE_SYSTEM      EventType = 1
	EventType_EVENT_TYPE_APPLICATION EventType = 2
	EventType_EVENT_TYPE_SECURITY    EventType = 3
	EventType_EVENT_TYPE_POLICY      EventType = 4
	EventType_EVENT_TYPE_APP_INSTALL EventType = 5
)

// EventLevel represents event severity.
type EventLevel int32

const (
	EventLevel_EVENT_LEVEL_UNSPECIFIED EventLevel = 0
	EventLevel_EVENT_LEVEL_DEBUG       EventLevel = 1
	EventLevel_EVENT_LEVEL_INFO        EventLevel = 2
	EventLevel_EVENT_LEVEL_WARNING     EventLevel = 3
	EventLevel_EVENT_LEVEL_ERROR       EventLevel = 4
	EventLevel_EVENT_LEVEL_CRITICAL    EventLevel = 5
)

// DeviceEvent represents a high level device event entry.
type DeviceEvent struct {
	EventId   string
	DeviceId  string
	Type      EventType
	Level     EventLevel
	Timestamp *timestamppb.Timestamp
	Message   string
	Metadata  map[string]string
	UserId    string
	AppId     string
}

// ReportEventsRequest batches events uploaded by the device.
type ReportEventsRequest struct {
	DeviceId    string
	DeviceToken string
	Events      []*DeviceEvent
	BatchTime   *timestamppb.Timestamp
}

// ReportEventsResponse summarises batch processing results.
type ReportEventsResponse struct {
	AcceptedEvents int32
	RejectedEvents int32
	ServerTime     *timestamppb.Timestamp
	CorrelationId  string
}

// AttestBootRequest carries TPM attestation evidence for the device boot sequence.
type AttestBootRequest struct {
	DeviceId      string
	DeviceToken   string
	Nonce         string
	ExpectedNonce string
	Quote         []byte
	Signature     []byte
	ProducedAt    *timestamppb.Timestamp
}

// AttestBootResponse reports the outcome of a TPM attestation attempt.
type AttestBootResponse struct {
	Verified      bool
	FailureReason string
	ServerTime    *timestamppb.Timestamp
	CorrelationId string
}

// Event represents a single detailed event payload.
type Event struct {
	EventId   string
	Timestamp *timestamppb.Timestamp
	EventType EventType
	Level     EventLevel
	Message   string
	Metadata  map[string]string
	Source    string
	Details   map[string]string
}

// AdminRole enumerates admin privilege tiers.
type AdminRole int32

const (
	AdminRole_ADMIN_ROLE_UNSPECIFIED AdminRole = 0
	AdminRole_ADMIN_ROLE_OWNER       AdminRole = 1
	AdminRole_ADMIN_ROLE_ADMIN       AdminRole = 2
	AdminRole_ADMIN_ROLE_AUDITOR     AdminRole = 3
)

// AdminUser describes an Evergreen admin account.
type AdminUser struct {
	Id          string
	TenantId    string
	Username    string
	Email       string
	Role        AdminRole
	CreatedAt   *timestamppb.Timestamp
	UpdatedAt   *timestamppb.Timestamp
	LastLoginAt *timestamppb.Timestamp
}

// CreateAdminUserRequest carries the data required to provision a new admin.
type CreateAdminUserRequest struct {
	TenantId string
	Username string
	Email    string
	Password string
	Role     AdminRole
}

// CreateAdminUserResponse returns the provisioned admin record.
type CreateAdminUserResponse struct {
	User *AdminUser
}

// AdminLoginRequest captures username/password credentials for authentication.
type AdminLoginRequest struct {
	Username string
	Password string
}

// AdminLoginResponse returns a signed JWT for console integrations.
type AdminLoginResponse struct {
	AccessToken string
	ExpiresAt   *timestamppb.Timestamp
	User        *AdminUser
}

// ListAdminUsersRequest pages through admin users within a tenant.
type ListAdminUsersRequest struct {
	TenantId  string
	PageSize  int32
	PageToken string
}

// ListAdminUsersResponse returns a page of admin users.
type ListAdminUsersResponse struct {
	Users         []*AdminUser
	NextPageToken string
}

// Tenant represents a managed organisation within Evergreen.
type Tenant struct {
	Id         string
	TenantCode string
	Name       string
	CreatedAt  *timestamppb.Timestamp
	UpdatedAt  *timestamppb.Timestamp
}

// CreateTenantRequest provisions a new tenant with an enrollment secret.
type CreateTenantRequest struct {
	TenantCode       string
	Name             string
	EnrollmentSecret string
}

// CreateTenantResponse returns the newly created tenant record.
type CreateTenantResponse struct {
	Tenant *Tenant
}

// ListTenantsRequest pages through known tenants.
type ListTenantsRequest struct {
	PageSize  int32
	PageToken string
}

// ListTenantsResponse returns a page of tenants.
type ListTenantsResponse struct {
	Tenants       []*Tenant
	NextPageToken string
}

// RotateTenantSecretRequest rotates the enrollment secret for a tenant.
type RotateTenantSecretRequest struct {
	TenantId         string
	EnrollmentSecret string
}

// RotateTenantSecretResponse returns the updated tenant record after rotation.
type RotateTenantSecretResponse struct {
	Tenant *Tenant
}

// ReportEventRequest uploads a single event.
type ReportEventRequest struct {
	DeviceId    string
	DeviceToken string
	Event       *Event
	RequestTime *timestamppb.Timestamp
	Nonce       string
}

// ReportEventResponse describes the outcome of a single event submission.
type ReportEventResponse struct {
	Success       bool
	ServerTime    *timestamppb.Timestamp
	CorrelationId string
	EventId       string
	ErrorMessage  string
}

// PolicyBundle models the collection of Evergreen policies for a device.
type PolicyBundle struct {
	Id           string
	Name         string
	Version      *timestamppb.Timestamp
	Apps         *AppPolicy
	Updates      *UpdatePolicy
	Browser      *BrowserPolicy
	Network      *NetworkPolicy
	Security     *SecurityPolicy
	Signature    string
	SigningKeyId string
}

// AppPolicy defines application policy constraints.
type AppPolicy struct {
	Packages              []*AppPackage
	AutoInstallRequired   bool
	AutoRemoveForbidden   bool
	InstallTimeoutSeconds int32
}

// AppPackage describes a single Flatpak package entry for policy.
type AppPackage struct {
	FlatpakRef  string
	Requirement AppRequirement
	DisplayName string
	Description string
}

// AppRequirement defines how a given package should be treated.
type AppRequirement int32

const (
	AppRequirement_APP_REQUIREMENT_UNSPECIFIED AppRequirement = 0
	AppRequirement_APP_REQUIREMENT_REQUIRED    AppRequirement = 1
	AppRequirement_APP_REQUIREMENT_OPTIONAL    AppRequirement = 2
	AppRequirement_APP_REQUIREMENT_FORBIDDEN   AppRequirement = 3
)

// UpdatePolicy defines operating system update rules.
type UpdatePolicy struct {
	Channel        UpdateChannel
	AutoInstall    bool
	AutoReboot     bool
	RebootWindow   string
	MaxDeferHours  int32
	AllowUserDefer bool
}

// UpdateChannel enumerates release channels supported by EvergreenOS.
type UpdateChannel int32

const (
	UpdateChannel_UPDATE_CHANNEL_UNSPECIFIED UpdateChannel = 0
	UpdateChannel_UPDATE_CHANNEL_STABLE      UpdateChannel = 1
	UpdateChannel_UPDATE_CHANNEL_BETA        UpdateChannel = 2
)

// BrowserPolicy defines browser settings enforced by EvergreenOS.
type BrowserPolicy struct {
	Homepage               string
	ForceInstallExtensions []string
	BlockedExtensions      []string
	AllowDeveloperTools    bool
	AllowPrivateBrowsing   bool
	AllowedUrls            []string
	BlockedUrls            []string
}

// NetworkPolicy defines WiFi and networking behaviour for managed devices.
type NetworkPolicy struct {
	WifiNetworks      []*WiFiConfig
	AllowManualConfig bool
	AllowTethering    bool
}

// WiFiConfig represents a configured WiFi network entry.
type WiFiConfig struct {
	Ssid        string
	Security    string
	Password    string
	AutoConnect bool
	Hidden      bool
}

// SecurityPolicy captures security posture and requirements for devices.
type SecurityPolicy struct {
	SelinuxEnforcing         bool
	DisableSsh               bool
	DisableUsbNewDevices     bool
	RequireScreenLock        bool
	ScreenLockTimeoutSeconds int32
	EnforceScreenLock        bool
}

// CreatePolicyRequest creates a new policy bundle for a tenant.
type CreatePolicyRequest struct {
	TenantId string
	Name     string
	Policy   *PolicyBundle
}

// CreatePolicyResponse returns the created policy bundle.
type CreatePolicyResponse struct {
	Policy *PolicyBundle
}

// UpdatePolicyRequest updates an existing policy bundle.
type UpdatePolicyRequest struct {
	PolicyId string
	Name     string
	Policy   *PolicyBundle
}

// UpdatePolicyResponse returns the updated policy bundle.
type UpdatePolicyResponse struct {
	Policy *PolicyBundle
}

// GetPolicyRequest retrieves a policy by identifier.
type GetPolicyRequest struct {
	PolicyId string
}

// GetPolicyResponse returns the requested policy bundle.
type GetPolicyResponse struct {
	Policy *PolicyBundle
}

// DeletePolicyRequest removes a policy bundle.
type DeletePolicyRequest struct {
	PolicyId string
}

// DeletePolicyResponse is returned after successful deletion.
type DeletePolicyResponse struct{}

// ListPoliciesRequest pages through policies for a tenant.
type ListPoliciesRequest struct {
	TenantId  string
	PageSize  int32
	PageToken string
}

// ListPoliciesResponse returns a page of policy bundles.
type ListPoliciesResponse struct {
	Policies      []*PolicyBundle
	NextPageToken string
}

// DeviceState represents a device telemetry report.
type DeviceState struct {
	DeviceId        string
	ActivePolicyId  string
	PolicyAppliedAt *timestamppb.Timestamp
	InstalledApps   []*InstalledApp
	UpdateStatus    *UpdateStatus
	Health          *DeviceHealth
	LastError       string
	ReportedAt      *timestamppb.Timestamp
}

// InstalledApp represents a single installed Flatpak application.
type InstalledApp struct {
	FlatpakRef  string
	Version     string
	InstalledAt *timestamppb.Timestamp
	IsRunning   bool
	LastUpdated *timestamppb.Timestamp
}

// UpdateStatusType enumerates device update states.
type UpdateStatusType int32

const (
	UpdateStatusType_UPDATE_STATUS_TYPE_UNSPECIFIED     UpdateStatusType = 0
	UpdateStatusType_UPDATE_STATUS_TYPE_IDLE            UpdateStatusType = 1
	UpdateStatusType_UPDATE_STATUS_TYPE_CHECKING        UpdateStatusType = 2
	UpdateStatusType_UPDATE_STATUS_TYPE_DOWNLOADING     UpdateStatusType = 3
	UpdateStatusType_UPDATE_STATUS_TYPE_INSTALLING      UpdateStatusType = 4
	UpdateStatusType_UPDATE_STATUS_TYPE_REBOOT_REQUIRED UpdateStatusType = 5
	UpdateStatusType_UPDATE_STATUS_TYPE_FAILED          UpdateStatusType = 6
)

// UpdateStatus represents the software update state of a device.
type UpdateStatus struct {
	Status           UpdateStatusType
	Channel          UpdateChannel
	AvailableVersion string
	DownloadProgress float32
	ErrorMessage     string
	LastCheck        *timestamppb.Timestamp
}

// DeviceHealth captures operational metrics for a device.
type DeviceHealth struct {
	AvailableDiskBytes  int64
	CpuUsagePercent     float32
	MemoryUsagePercent  float32
	BatteryLevelPercent float32
	IsCharging          bool
	UptimeSeconds       int64
}
