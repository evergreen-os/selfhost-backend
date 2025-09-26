package devices

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/evergreenos/selfhost-backend/internal/db"
	generated "github.com/evergreenos/selfhost-backend/internal/db/generated"
	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"github.com/jackc/pgx/v5/pgtype"
)

// StateProcessor handles device state processing and analysis
type StateProcessor struct {
	db *db.DB
}

// NewStateProcessor creates a new state processor
func NewStateProcessor(database *db.DB) *StateProcessor {
	return &StateProcessor{
		db: database,
	}
}

// ProcessDeviceState processes and analyzes incoming device state
func (sp *StateProcessor) ProcessDeviceState(ctx context.Context, deviceID string, state *pb.DeviceState) (*StateAnalysis, error) {
	if state == nil {
		return nil, fmt.Errorf("device state is required")
	}

	analysis := &StateAnalysis{
		DeviceID:    deviceID,
		ProcessedAt: time.Now(),
		Alerts:      []string{},
		Recommendations: []string{},
	}

	// Validate state consistency
	if err := sp.validateStateConsistency(state); err != nil {
		analysis.ValidationErrors = append(analysis.ValidationErrors, err.Error())
	}

	// Analyze device health
	if state.Health != nil {
		sp.analyzeDeviceHealth(state.Health, analysis)
	}

	// Analyze installed applications
	if len(state.InstalledApps) > 0 {
		sp.analyzeInstalledApps(state.InstalledApps, analysis)
	}

	// Analyze update status
	if state.UpdateStatus != nil {
		sp.analyzeUpdateStatus(state.UpdateStatus, analysis)
	}

	// Check policy compliance
	if state.ActivePolicyId != "" {
		if err := sp.checkPolicyCompliance(ctx, deviceID, state); err != nil {
			analysis.PolicyViolations = append(analysis.PolicyViolations, err.Error())
		}
	}

	// Store state in database
	if err := sp.storeDeviceState(ctx, deviceID, state, analysis); err != nil {
		return nil, fmt.Errorf("failed to store device state: %w", err)
	}

	return analysis, nil
}

// StateAnalysis contains the results of device state processing
type StateAnalysis struct {
	DeviceID          string
	ProcessedAt       time.Time
	ValidationErrors  []string
	Alerts            []string
	Recommendations   []string
	PolicyViolations  []string
	RequiresPolicyPull bool
	NextReportInterval time.Duration
}

// validateStateConsistency performs comprehensive state validation
func (sp *StateProcessor) validateStateConsistency(state *pb.DeviceState) error {
	now := time.Now()

	// Check timestamps
	if state.ReportedAt != nil {
		reportTime := state.ReportedAt.AsTime()
		if reportTime.After(now.Add(5 * time.Minute)) {
			return fmt.Errorf("report timestamp is too far in the future")
		}
		if reportTime.Before(now.Add(-24 * time.Hour)) {
			return fmt.Errorf("report timestamp is too old (more than 24 hours)")
		}
	}

	// Check policy consistency
	if state.ActivePolicyId != "" && state.PolicyAppliedAt == nil {
		return fmt.Errorf("active policy ID set but no policy applied timestamp")
	}

	if state.PolicyAppliedAt != nil {
		policyTime := state.PolicyAppliedAt.AsTime()
		if policyTime.After(now) {
			return fmt.Errorf("policy applied timestamp is in the future")
		}
	}

	// Check application consistency
	for _, app := range state.InstalledApps {
		if app.InstalledAt != nil && app.LastUpdated != nil {
			if app.LastUpdated.AsTime().Before(app.InstalledAt.AsTime()) {
				return fmt.Errorf("application %s: last updated time is before installation time", app.FlatpakRef)
			}
		}
	}

	return nil
}

// analyzeDeviceHealth analyzes device health metrics and generates alerts
func (sp *StateProcessor) analyzeDeviceHealth(health *pb.DeviceHealth, analysis *StateAnalysis) {
	// Check disk space
	if health.AvailableDiskBytes < 1024*1024*1024 { // Less than 1GB
		analysis.Alerts = append(analysis.Alerts, "Critical: Low disk space (less than 1GB available)")
	} else if health.AvailableDiskBytes < 5*1024*1024*1024 { // Less than 5GB
		analysis.Alerts = append(analysis.Alerts, "Warning: Low disk space (less than 5GB available)")
	}

	// Check CPU usage
	if health.CpuUsagePercent > 90 {
		analysis.Alerts = append(analysis.Alerts, "Critical: High CPU usage (>90%)")
	} else if health.CpuUsagePercent > 70 {
		analysis.Alerts = append(analysis.Alerts, "Warning: High CPU usage (>70%)")
	}

	// Check memory usage
	if health.MemoryUsagePercent > 90 {
		analysis.Alerts = append(analysis.Alerts, "Critical: High memory usage (>90%)")
	} else if health.MemoryUsagePercent > 80 {
		analysis.Alerts = append(analysis.Alerts, "Warning: High memory usage (>80%)")
	}

	// Check battery status
	if health.BatteryLevelPercent >= 0 { // Has battery
		if health.BatteryLevelPercent < 10 {
			analysis.Alerts = append(analysis.Alerts, "Critical: Low battery level (<10%)")
		} else if health.BatteryLevelPercent < 20 {
			analysis.Alerts = append(analysis.Alerts, "Warning: Low battery level (<20%)")
		}

		if !health.IsCharging && health.BatteryLevelPercent < 30 {
			analysis.Recommendations = append(analysis.Recommendations, "Consider connecting charger - battery level is low")
		}
	}

	// Check uptime
	if health.UptimeSeconds > 30*24*3600 { // More than 30 days
		analysis.Recommendations = append(analysis.Recommendations, "Device has been running for over 30 days - consider rebooting")
	}
}

// analyzeInstalledApps analyzes installed applications for policy compliance and issues
func (sp *StateProcessor) analyzeInstalledApps(apps []*pb.InstalledApp, analysis *StateAnalysis) {
	runningApps := 0
	outdatedApps := 0
	now := time.Now()

	for _, app := range apps {
		if app.IsRunning {
			runningApps++
		}

		// Check for potentially outdated apps
		if app.LastUpdated != nil {
			daysSinceUpdate := now.Sub(app.LastUpdated.AsTime()).Hours() / 24
			if daysSinceUpdate > 90 { // More than 90 days
				outdatedApps++
			}
		}

		// Check for installation consistency
		if app.InstalledAt != nil && app.InstalledAt.AsTime().After(now) {
			analysis.ValidationErrors = append(analysis.ValidationErrors,
				fmt.Sprintf("Application %s has future installation timestamp", app.FlatpakRef))
		}
	}

	if runningApps > 20 {
		analysis.Recommendations = append(analysis.Recommendations,
			fmt.Sprintf("High number of running applications (%d) - consider closing unused apps", runningApps))
	}

	if outdatedApps > 0 {
		analysis.Recommendations = append(analysis.Recommendations,
			fmt.Sprintf("%d applications haven't been updated in over 90 days", outdatedApps))
	}
}

// analyzeUpdateStatus analyzes system update status and generates recommendations
func (sp *StateProcessor) analyzeUpdateStatus(updateStatus *pb.UpdateStatus, analysis *StateAnalysis) {
	now := time.Now()

	// Check last update check time
	if updateStatus.LastCheck != nil {
		hoursSinceCheck := now.Sub(updateStatus.LastCheck.AsTime()).Hours()
		if hoursSinceCheck > 48 { // More than 48 hours
			analysis.Recommendations = append(analysis.Recommendations, "Update check is overdue (more than 48 hours)")
		}
	}

	// Analyze update status
	switch updateStatus.Status {
	case pb.UpdateStatusType_UPDATE_STATUS_TYPE_FAILED:
		analysis.Alerts = append(analysis.Alerts, "Critical: System update failed")
		if updateStatus.ErrorMessage != "" {
			analysis.Alerts = append(analysis.Alerts, fmt.Sprintf("Update error: %s", updateStatus.ErrorMessage))
		}

	case pb.UpdateStatusType_UPDATE_STATUS_TYPE_REBOOT_REQUIRED:
		analysis.Alerts = append(analysis.Alerts, "Warning: System reboot required to complete updates")
		analysis.Recommendations = append(analysis.Recommendations, "Schedule a system reboot to complete pending updates")

	case pb.UpdateStatusType_UPDATE_STATUS_TYPE_DOWNLOADING:
		if updateStatus.DownloadProgress < 100 {
			analysis.Recommendations = append(analysis.Recommendations,
				fmt.Sprintf("System update in progress (%.1f%% complete)", updateStatus.DownloadProgress))
		}

	case pb.UpdateStatusType_UPDATE_STATUS_TYPE_INSTALLING:
		analysis.Recommendations = append(analysis.Recommendations, "System update installation in progress")

	case pb.UpdateStatusType_UPDATE_STATUS_TYPE_IDLE:
		if updateStatus.AvailableVersion != "" {
			analysis.Recommendations = append(analysis.Recommendations,
				fmt.Sprintf("System update available: %s", updateStatus.AvailableVersion))
		}
	}

	// Check update channel consistency
	if updateStatus.Channel == pb.UpdateChannel_UPDATE_CHANNEL_UNSPECIFIED {
		analysis.ValidationErrors = append(analysis.ValidationErrors, "Update channel not specified")
	}
}

// checkPolicyCompliance verifies that the device state complies with active policy
func (sp *StateProcessor) checkPolicyCompliance(ctx context.Context, deviceID string, state *pb.DeviceState) error {
	// This would normally check against the actual policy from the database
	// For now, implement basic compliance checks

	// Check if policy is reasonably recent
	if state.PolicyAppliedAt != nil {
		policyAge := time.Since(state.PolicyAppliedAt.AsTime())
		if policyAge > 7*24*time.Hour { // More than 7 days old
			return fmt.Errorf("policy is over 7 days old - may need refresh")
		}
	}

	// Check for required applications (this would come from policy)
	requiredApps := []string{
		"org.mozilla.firefox",
		// Add more required apps based on policy
	}

	installedAppRefs := make(map[string]bool)
	for _, app := range state.InstalledApps {
		installedAppRefs[app.FlatpakRef] = true
	}

	for _, requiredApp := range requiredApps {
		if !installedAppRefs[requiredApp] {
			return fmt.Errorf("required application not installed: %s", requiredApp)
		}
	}

	return nil
}

// storeDeviceState stores the device state and analysis in the database
func (sp *StateProcessor) storeDeviceState(ctx context.Context, deviceID string, state *pb.DeviceState, analysis *StateAnalysis) error {
	// Serialize state to JSON
	stateJSON, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to serialize device state: %w", err)
	}

	// Serialize analysis to JSON
	analysisJSON, err := json.Marshal(analysis)
	if err != nil {
		return fmt.Errorf("failed to serialize state analysis: %w", err)
	}

	// Convert device ID string to UUID
	var deviceUUID pgtype.UUID
	if err := deviceUUID.Scan(deviceID); err != nil {
		return fmt.Errorf("failed to convert device ID to UUID: %w", err)
	}

	// Store in device_states table
	_, err = sp.db.Queries().UpsertDeviceState(ctx, generated.UpsertDeviceStateParams{
		DeviceID:        deviceUUID,
		ActivePolicyID:  &state.ActivePolicyId,
		PolicyAppliedAt: pgtype.Timestamptz{Time: state.PolicyAppliedAt.AsTime(), Valid: state.PolicyAppliedAt != nil},
		InstalledApps:   stateJSON, // Store full state as JSON for now
		UpdateStatus:    analysisJSON, // Store analysis as JSON for now
		HealthMetrics:   stateJSON, // Store full state as JSON for now
		LastError:       nil, // Will be populated if there are errors
		ReportedAt:      pgtype.Timestamptz{Time: state.ReportedAt.AsTime(), Valid: state.ReportedAt != nil},
	})
	if err != nil {
		return fmt.Errorf("failed to store device state: %w", err)
	}

	// Create events for critical alerts
	for _, alert := range analysis.Alerts {
		if containsString(alert, "Critical:") {
			if err := sp.createAlertEvent(ctx, deviceID, alert); err != nil {
				// Log but don't fail the entire operation
				fmt.Printf("Failed to create alert event: %v\n", err)
			}
		}
	}

	return nil
}

// createAlertEvent creates an event for critical alerts
func (sp *StateProcessor) createAlertEvent(ctx context.Context, deviceID, alertMessage string) error {
	eventID := fmt.Sprintf("alert-%d", time.Now().UnixNano())

	// Convert device ID string to UUID
	var deviceUUID pgtype.UUID
	if err := deviceUUID.Scan(deviceID); err != nil {
		return fmt.Errorf("failed to convert device ID to UUID: %w", err)
	}

	_, err := sp.db.Queries().CreateEvent(ctx, generated.CreateEventParams{
		EventID:      eventID,
		DeviceID:     deviceUUID,
		EventType:    "system_alert",
		EventLevel:   "error",
		Message:      alertMessage,
		Metadata:     []byte("{}"),
		UserID:       nil,
		AppID:        nil,
		PolicyID:     nil,
		ErrorDetails: nil,
	})

	return err
}

// DeterminePolicyPullRequired checks if the device should pull a new policy
func (sp *StateProcessor) DeterminePolicyPullRequired(ctx context.Context, deviceID string, state *pb.DeviceState) (bool, string, error) {
	// Get device from database to check tenant
	device, err := sp.db.Queries().GetDeviceByID(ctx, deviceID)
	if err != nil {
		return false, "", fmt.Errorf("failed to get device: %w", err)
	}

	// Get latest policy for tenant
	latestPolicy, err := sp.db.Queries().GetLatestPolicyByTenant(ctx, device.TenantID)
	if err != nil {
		// No policy found - device should continue with current state
		return false, "", nil
	}

	// Check if device has newer policy than what it's currently using
	if state.ActivePolicyId != latestPolicy.PolicyID {
		return true, "New policy available", nil
	}

	// Check if policy applied time is significantly older than policy version
	if state.PolicyAppliedAt != nil {
		policyAge := time.Since(state.PolicyAppliedAt.AsTime())
		latestPolicyAge := time.Since(latestPolicy.VersionTimestamp.Time)

		if policyAge > latestPolicyAge+time.Hour { // Applied policy is more than 1 hour older
			return true, "Policy version mismatch detected", nil
		}
	}

	return false, "", nil
}

// CalculateNextReportInterval determines when the device should report next
func (sp *StateProcessor) CalculateNextReportInterval(analysis *StateAnalysis) int32 {
	baseInterval := int32(300) // 5 minutes default

	// Increase frequency if there are critical alerts
	criticalAlerts := 0
	for _, alert := range analysis.Alerts {
		if containsString(alert, "Critical:") {
			criticalAlerts++
		}
	}

	if criticalAlerts > 0 {
		return baseInterval / 2 // Report more frequently (2.5 minutes) if critical issues
	}

	// Increase frequency if there are policy violations
	if len(analysis.PolicyViolations) > 0 {
		return baseInterval / 2 // Report more frequently for policy issues
	}

	// Normal interval for healthy devices
	if len(analysis.Alerts) == 0 && len(analysis.ValidationErrors) == 0 {
		return baseInterval * 2 // Report less frequently (10 minutes) if all is well
	}

	return baseInterval
}

// Helper function to check if a string contains a substring
func containsString(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		   findString(haystack, needle) >= 0
}

// Helper function to find a substring
func findString(haystack, needle string) int {
	if len(needle) == 0 {
		return 0
	}
	if len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}