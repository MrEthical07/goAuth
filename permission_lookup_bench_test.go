package goAuth

import (
	"testing"
)

func BenchmarkPermissionRegistryBitLookup(b *testing.B) {
	engine, cleanup := newBenchmarkEngine(b, ModeJWTOnly)
	defer cleanup()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, ok := engine.registry.Bit("perm.read"); !ok {
			b.Fatal("permission bit missing")
		}
	}
}

func BenchmarkPermissionEngineHasPermission(b *testing.B) {
	engine, cleanup := newBenchmarkEngine(b, ModeJWTOnly)
	defer cleanup()

	mask, ok := engine.roleManager.GetMask("admin")
	if !ok {
		b.Fatal("admin role mask missing")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if !engine.HasPermission(mask, "perm.read") {
			b.Fatal("expected permission grant")
		}
	}
}
