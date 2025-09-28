package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	pb "github.com/evergreenos/selfhost-backend/gen/go/evergreen/v1"
	"github.com/evergreenos/selfhost-backend/internal/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type healthPayload struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// DeviceAPI exposes the EvergreenOS device lifecycle operations used by the REST facade.
type DeviceAPI interface {
	EnrollDevice(ctx context.Context, req *pb.EnrollDeviceRequest) (*pb.EnrollDeviceResponse, error)
	PullPolicy(ctx context.Context, req *pb.PullPolicyRequest) (*pb.PullPolicyResponse, error)
	ReportState(ctx context.Context, req *pb.ReportStateRequest) (*pb.ReportStateResponse, error)
	ReportEvents(ctx context.Context, req *pb.ReportEventsRequest) (*pb.ReportEventsResponse, error)
	AttestBoot(ctx context.Context, req *pb.AttestBootRequest) (*pb.AttestBootResponse, error)
}

// AdminAPI exposes admin console operations for REST translation.
type AdminAPI interface {
	Login(ctx context.Context, req *pb.AdminLoginRequest) (*pb.AdminLoginResponse, error)
	CreateUserWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.CreateAdminUserRequest) (*pb.CreateAdminUserResponse, error)
	ListUsersWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.ListAdminUsersRequest) (*pb.ListAdminUsersResponse, error)
}

// PolicyAPI exposes policy administration operations for REST translation.
type PolicyAPI interface {
	CreatePolicyWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.CreatePolicyRequest) (*pb.CreatePolicyResponse, error)
	UpdatePolicyWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.UpdatePolicyRequest) (*pb.UpdatePolicyResponse, error)
	DeletePolicyWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.DeletePolicyRequest) (*pb.DeletePolicyResponse, error)
	GetPolicyWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.GetPolicyRequest) (*pb.GetPolicyResponse, error)
	ListPoliciesWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.ListPoliciesRequest) (*pb.ListPoliciesResponse, error)
}

// TenantAPI exposes tenant management operations for REST translation.
type TenantAPI interface {
	CreateTenantWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.CreateTenantRequest) (*pb.CreateTenantResponse, error)
	ListTenantsWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.ListTenantsRequest) (*pb.ListTenantsResponse, error)
	RotateTenantSecretWithClaims(ctx context.Context, actor *auth.AdminClaims, req *pb.RotateTenantSecretRequest) (*pb.RotateTenantSecretResponse, error)
}

// RouterConfig configures the REST router dependencies.
type RouterConfig struct {
	Device       DeviceAPI
	Admin        AdminAPI
	Policy       PolicyAPI
	Tenant       TenantAPI
	TokenManager *auth.Manager
}

// NewRouter returns an HTTP handler exposing device lifecycle REST endpoints and health probes.
func NewRouter(cfg RouterConfig) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, healthPayload{Status: "ok", Timestamp: time.Now().UTC()})
	})
        mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
                writeJSON(w, http.StatusOK, healthPayload{Status: "ready", Timestamp: time.Now().UTC()})
        })

        authHandler := func(fn func(http.ResponseWriter, *http.Request, *auth.AdminClaims)) http.HandlerFunc {
                return func(w http.ResponseWriter, r *http.Request) {
                        claims, err := authenticateAdmin(r, cfg.TokenManager)
                        if err != nil {
                                writeError(w, statusFromError(err), err)
                                return
                        }
                        fn(w, r, claims)
                }
        }

        if cfg.Device != nil {
                mux.HandleFunc("POST /v1/devices/enroll", func(w http.ResponseWriter, r *http.Request) {
                        var req pb.EnrollDeviceRequest
                        if err := decodeJSON(r.Body, &req); err != nil {
                                writeError(w, http.StatusBadRequest, err)
				return
			}
			resp, err := cfg.Device.EnrollDevice(r.Context(), &req)
			if err != nil {
				writeError(w, statusFromError(err), err)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		})

		mux.HandleFunc("POST /v1/devices/{deviceID}/state", func(w http.ResponseWriter, r *http.Request) {
			var req pb.ReportStateRequest
			if err := decodeJSON(r.Body, &req); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			req.DeviceId = r.PathValue("deviceID")
			resp, err := cfg.Device.ReportState(r.Context(), &req)
			if err != nil {
				writeError(w, statusFromError(err), err)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		})

		mux.HandleFunc("POST /v1/devices/{deviceID}/events", func(w http.ResponseWriter, r *http.Request) {
			var req pb.ReportEventsRequest
			if err := decodeJSON(r.Body, &req); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			req.DeviceId = r.PathValue("deviceID")
			resp, err := cfg.Device.ReportEvents(r.Context(), &req)
			if err != nil {
				writeError(w, statusFromError(err), err)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		})

		mux.HandleFunc("POST /v1/devices/{deviceID}/policy", func(w http.ResponseWriter, r *http.Request) {
			var req pb.PullPolicyRequest
			if err := decodeJSON(r.Body, &req); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			req.DeviceId = r.PathValue("deviceID")
			resp, err := cfg.Device.PullPolicy(r.Context(), &req)
			if err != nil {
				writeError(w, statusFromError(err), err)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		})

		mux.HandleFunc("POST /v1/devices/{deviceID}/attest", func(w http.ResponseWriter, r *http.Request) {
			var req pb.AttestBootRequest
			if err := decodeJSON(r.Body, &req); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			req.DeviceId = r.PathValue("deviceID")
			resp, err := cfg.Device.AttestBoot(r.Context(), &req)
			if err != nil {
				writeError(w, statusFromError(err), err)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		})
	}

        if cfg.Admin != nil {
                mux.HandleFunc("POST /v1/admin/login", func(w http.ResponseWriter, r *http.Request) {
                        var req pb.AdminLoginRequest
                        if err := decodeJSON(r.Body, &req); err != nil {
                                writeError(w, http.StatusBadRequest, err)
                                return
			}
			resp, err := cfg.Admin.Login(r.Context(), &req)
			if err != nil {
				writeError(w, statusFromError(err), err)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		})

                mux.HandleFunc("POST /v1/admin/users", authHandler(func(w http.ResponseWriter, r *http.Request, claims *auth.AdminClaims) {
                        var req pb.CreateAdminUserRequest
                        if err := decodeJSON(r.Body, &req); err != nil {
                                writeError(w, http.StatusBadRequest, err)
                                return
			}
			resp, err := cfg.Admin.CreateUserWithClaims(r.Context(), claims, &req)
			if err != nil {
				writeError(w, statusFromError(err), err)
				return
			}
			writeJSON(w, http.StatusCreated, resp)
		}))

		mux.HandleFunc("GET /v1/admin/users", authHandler(func(w http.ResponseWriter, r *http.Request, claims *auth.AdminClaims) {
			query := r.URL.Query()
			req := &pb.ListAdminUsersRequest{
				TenantId:  query.Get("tenant_id"),
				PageToken: query.Get("page_token"),
			}
			if size := query.Get("page_size"); size != "" {
				if parsed, err := strconv.Atoi(size); err == nil {
					req.PageSize = int32(parsed)
				} else {
					writeError(w, http.StatusBadRequest, fmt.Errorf("invalid page_size"))
					return
				}
			}
			resp, err := cfg.Admin.ListUsersWithClaims(r.Context(), claims, req)
			if err != nil {
				writeError(w, statusFromError(err), err)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		}))
	}

	if cfg.Policy != nil {
		mux.HandleFunc("POST /v1/admin/policies", authHandler(func(w http.ResponseWriter, r *http.Request, claims *auth.AdminClaims) {
			var req pb.CreatePolicyRequest
			if err := decodeJSON(r.Body, &req); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			resp, err := cfg.Policy.CreatePolicyWithClaims(r.Context(), claims, &req)
			if err != nil {
				writeError(w, statusFromError(err), err)
				return
			}
			writeJSON(w, http.StatusCreated, resp)
		}))

		mux.HandleFunc("PUT /v1/admin/policies/{policyID}", authHandler(func(w http.ResponseWriter, r *http.Request, claims *auth.AdminClaims) {
			var req pb.UpdatePolicyRequest
			if err := decodeJSON(r.Body, &req); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			req.PolicyId = r.PathValue("policyID")
			resp, err := cfg.Policy.UpdatePolicyWithClaims(r.Context(), claims, &req)
			if err != nil {
				writeError(w, statusFromError(err), err)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		}))

		mux.HandleFunc("GET /v1/admin/policies/{policyID}", authHandler(func(w http.ResponseWriter, r *http.Request, claims *auth.AdminClaims) {
			req := &pb.GetPolicyRequest{PolicyId: r.PathValue("policyID")}
			resp, err := cfg.Policy.GetPolicyWithClaims(r.Context(), claims, req)
			if err != nil {
				writeError(w, statusFromError(err), err)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		}))

		mux.HandleFunc("DELETE /v1/admin/policies/{policyID}", authHandler(func(w http.ResponseWriter, r *http.Request, claims *auth.AdminClaims) {
			req := &pb.DeletePolicyRequest{PolicyId: r.PathValue("policyID")}
			if _, err := cfg.Policy.DeletePolicyWithClaims(r.Context(), claims, req); err != nil {
				writeError(w, statusFromError(err), err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}))

		mux.HandleFunc("GET /v1/admin/policies", authHandler(func(w http.ResponseWriter, r *http.Request, claims *auth.AdminClaims) {
			query := r.URL.Query()
			req := &pb.ListPoliciesRequest{
				TenantId:  query.Get("tenant_id"),
				PageToken: query.Get("page_token"),
			}
			if size := query.Get("page_size"); size != "" {
				if parsed, err := strconv.Atoi(size); err == nil {
					req.PageSize = int32(parsed)
				} else {
					writeError(w, http.StatusBadRequest, fmt.Errorf("invalid page_size"))
					return
				}
			}
			resp, err := cfg.Policy.ListPoliciesWithClaims(r.Context(), claims, req)
			if err != nil {
				writeError(w, statusFromError(err), err)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		}))
	}

	if cfg.Tenant != nil {
		mux.HandleFunc("POST /v1/admin/tenants", authHandler(func(w http.ResponseWriter, r *http.Request, claims *auth.AdminClaims) {
			var req pb.CreateTenantRequest
			if err := decodeJSON(r.Body, &req); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			resp, err := cfg.Tenant.CreateTenantWithClaims(r.Context(), claims, &req)
			if err != nil {
				writeError(w, statusFromError(err), err)
				return
			}
			writeJSON(w, http.StatusCreated, resp)
		}))

		mux.HandleFunc("GET /v1/admin/tenants", authHandler(func(w http.ResponseWriter, r *http.Request, claims *auth.AdminClaims) {
			query := r.URL.Query()
			req := &pb.ListTenantsRequest{PageToken: query.Get("page_token")}
			if size := query.Get("page_size"); size != "" {
				if parsed, err := strconv.Atoi(size); err == nil {
					req.PageSize = int32(parsed)
				} else {
					writeError(w, http.StatusBadRequest, fmt.Errorf("invalid page_size"))
					return
				}
			}
			resp, err := cfg.Tenant.ListTenantsWithClaims(r.Context(), claims, req)
			if err != nil {
				writeError(w, statusFromError(err), err)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		}))

		mux.HandleFunc("POST /v1/admin/tenants/{tenantID}/rotate-secret", authHandler(func(w http.ResponseWriter, r *http.Request, claims *auth.AdminClaims) {
			var req pb.RotateTenantSecretRequest
			if err := decodeJSON(r.Body, &req); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			req.TenantId = r.PathValue("tenantID")
			resp, err := cfg.Tenant.RotateTenantSecretWithClaims(r.Context(), claims, &req)
			if err != nil {
				writeError(w, statusFromError(err), err)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		}))
	}

	return mux
}

func decodeJSON(body io.ReadCloser, out any) error {
	defer body.Close()
	dec := json.NewDecoder(body)
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("request body required")
		}
		return fmt.Errorf("invalid json payload: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{"error": err.Error()})
}

func statusFromError(err error) int {
	var httpErr interface{ HTTPStatus() int }
	if errors.As(err, &httpErr) {
		return httpErr.HTTPStatus()
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.InvalidArgument:
			return http.StatusBadRequest
		case codes.NotFound:
			return http.StatusNotFound
		case codes.Unauthenticated:
			return http.StatusUnauthorized
		case codes.PermissionDenied:
			return http.StatusForbidden
		case codes.AlreadyExists:
			return http.StatusConflict
		default:
			return http.StatusInternalServerError
		}
	}
	return http.StatusInternalServerError
}

func authenticateAdmin(r *http.Request, manager *auth.Manager) (*auth.AdminClaims, error) {
	if manager == nil {
		return nil, status.Error(codes.Internal, "admin authentication not configured")
	}
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, status.Error(codes.Unauthenticated, "authorization header required")
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, status.Error(codes.Unauthenticated, "bearer token required")
	}
	claims, err := manager.ParseAdminToken(parts[1])
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid admin token")
	}
	return claims, nil
}
