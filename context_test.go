package goAuth

import (
	"context"
	"testing"
)

func TestTenantIDFromContext(t *testing.T) {
	tests := []struct {
		name   string
		ctx    func() context.Context
		want   string
		wantOK bool
	}{
		{
			name:   "nil context",
			ctx:    func() context.Context { return nil },
			want:   "",
			wantOK: false,
		},
		{
			name:   "no tenant attached",
			ctx:    context.Background,
			want:   "",
			wantOK: false,
		},
		{
			name:   "tenant attached",
			ctx:    func() context.Context { return WithTenantID(context.Background(), "tenant-a") },
			want:   "tenant-a",
			wantOK: true,
		},
		{
			name:   "explicit default tenant is returned as attached",
			ctx:    func() context.Context { return WithTenantID(context.Background(), "0") },
			want:   "0",
			wantOK: true,
		},
		{
			name:   "empty tenant is treated as absent",
			ctx:    func() context.Context { return WithTenantID(context.Background(), "") },
			want:   "",
			wantOK: false,
		},
		{
			name: "innermost attachment wins",
			ctx: func() context.Context {
				return WithTenantID(WithTenantID(context.Background(), "outer"), "inner")
			},
			want:   "inner",
			wantOK: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := TenantIDFromContext(tc.ctx())
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("TenantIDFromContext() = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// The unexported resolver keeps synthesizing "0"; the exported reader must
// not, otherwise it could not distinguish "unset" from "tenant 0".
func TestTenantIDFromContextDoesNotSynthesizeDefault(t *testing.T) {
	ctx := context.Background()
	if got := tenantIDFromContext(ctx); got != "0" {
		t.Fatalf("internal resolver default = %q, want %q", got, "0")
	}
	if got, ok := TenantIDFromContext(ctx); ok || got != "" {
		t.Fatalf("exported reader synthesized a tenant: (%q, %v)", got, ok)
	}
}
