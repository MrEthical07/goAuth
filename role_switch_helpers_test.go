package goAuth

import (
	"context"
	"sync"
)

type canAssumeCall struct {
	tenantID string
	userID   string
	role     string
}

// roleSwitchMockProvider is a tenant-aware UserProvider that also implements
// RoleSwitchProvider. roles maps userID to the set of roles the account
// holds; a user with no entry holds nothing, so tests grant the primary role
// explicitly, as the provider contract requires.
type roleSwitchMockProvider struct {
	tenantMockProvider

	rmu          sync.Mutex
	roles        map[string]map[string]bool
	canCalls     []canAssumeCall
	canErr       error
	ignoreTenant bool
}

func newRoleSwitchMockProvider() *roleSwitchMockProvider {
	return &roleSwitchMockProvider{
		tenantMockProvider: *newTenantMockProvider(),
		roles:              make(map[string]map[string]bool),
	}
}

func (p *roleSwitchMockProvider) grant(userID string, roles ...string) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	set := p.roles[userID]
	if set == nil {
		set = make(map[string]bool)
		p.roles[userID] = set
	}
	for _, r := range roles {
		set[r] = true
	}
}

func (p *roleSwitchMockProvider) revoke(userID, role string) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	delete(p.roles[userID], role)
}

func (p *roleSwitchMockProvider) setCanErr(err error) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	p.canErr = err
}

func (p *roleSwitchMockProvider) callCount() int {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	return len(p.canCalls)
}

func (p *roleSwitchMockProvider) lastCall() canAssumeCall {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	if len(p.canCalls) == 0 {
		return canAssumeCall{}
	}
	return p.canCalls[len(p.canCalls)-1]
}

// GetUserByIDInTenant serializes the embedded provider's lookup, which
// updates counters without a lock; concurrent switches call it in parallel.
func (p *roleSwitchMockProvider) GetUserByIDInTenant(ctx context.Context, tenantID, userID string) (UserRecord, error) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	return p.tenantMockProvider.GetUserByIDInTenant(ctx, tenantID, userID)
}

func (p *roleSwitchMockProvider) CanAssumeRole(ctx context.Context, tenantID, userID, role string) (bool, error) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	p.canCalls = append(p.canCalls, canAssumeCall{tenantID: tenantID, userID: userID, role: role})
	if p.canErr != nil {
		return false, p.canErr
	}
	if !p.ignoreTenant {
		if user, ok := p.users[userID]; ok && user.TenantID != tenantID {
			return false, nil
		}
	}
	return p.roles[userID][role], nil
}
