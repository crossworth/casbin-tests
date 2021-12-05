package main

import (
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/stretchr/testify/require"
)

func TestCasbin(t *testing.T) {
	text := `
[request_definition]
r = subject, resource, action
r2 = subject, team, resource, action
r3 = subject, team, plan, resource, action

[policy_definition]
p = subject, resource, action
p2 = subject, team, resource, action
p3 = subject, team, plan, resource, action

[policy_effect]
e = some(where (p.eft == allow))
e2 = some(where (p.eft == allow))
e3 = some(where (p.eft == allow))

[matchers]
m = r.subject == p.subject && keyMatch(r.resource, p.resource) && (r.action == p.action || p.action == "*")
m2 = r2.subject == p2.subject && r2.team == p2.team && keyMatch(r2.resource, p2.resource) && (r2.action == p2.action || p2.action == "*")
m3 = r3.subject == p3.subject && r3.team == p3.team && r3.plan == p3.plan && keyMatch(r3.resource, p3.resource) && (r3.action == p3.action || p3.action == "*")
`
	m, err := model.NewModelFromString(text)
	require.NoError(t, err)

	a := fileadapter.NewAdapter("./policy.csv")

	authEnforcer, err := casbin.NewEnforcer(m, a)
	require.NoError(t, err)

	t.Run("global resource", func(t *testing.T) {
		r, err := authEnforcer.Enforce("user:1", "team", "create")
		require.NoError(t, err)
		require.True(t, r)

		r, err = authEnforcer.Enforce("user:100", "team", "create")
		require.NoError(t, err)
		require.False(t, r)

		r, err = authEnforcer.Enforce("user:100", "withdraw", "create")
		require.NoError(t, err)
		require.False(t, r)

		r, err = authEnforcer.Enforce("user:1", "team", "delete")
		require.NoError(t, err)
		require.False(t, r)
	})

	t.Run("team resource", func(t *testing.T) {
		enforcerContext := casbin.NewEnforceContext("2")
		r, err := authEnforcer.Enforce(enforcerContext, "user:1", "team:2", "plan", "create")
		require.NoError(t, err)
		require.True(t, r)

		r, err = authEnforcer.Enforce(enforcerContext, "user:100", "team:2", "plan", "create")
		require.NoError(t, err)
		require.False(t, r)

		r, err = authEnforcer.Enforce(enforcerContext, "user:1", "team:200", "plan", "create")
		require.NoError(t, err)
		require.False(t, r)

		r, err = authEnforcer.Enforce(enforcerContext, "user:1", "team:2", "withdraw", "create")
		require.NoError(t, err)
		require.False(t, r)

		r, err = authEnforcer.Enforce(enforcerContext, "user:1", "team:2", "plan", "delete")
		require.NoError(t, err)
		require.False(t, r)
	})

	t.Run("team plan resource", func(t *testing.T) {
		enforcerContext := casbin.NewEnforceContext("3")
		r, err := authEnforcer.Enforce(enforcerContext, "user:1", "team:2", "plan:3", "tip", "create")
		require.NoError(t, err)
		require.True(t, r)

		r, err = authEnforcer.Enforce(enforcerContext, "user:100", "team:2", "plan:3", "tip", "create")
		require.NoError(t, err)
		require.False(t, r)

		r, err = authEnforcer.Enforce(enforcerContext, "user:1", "team:200", "plan:3", "tip", "create")
		require.NoError(t, err)
		require.False(t, r)

		r, err = authEnforcer.Enforce(enforcerContext, "user:1", "team:2", "plan:300", "tip", "create")
		require.NoError(t, err)
		require.False(t, r)

		r, err = authEnforcer.Enforce(enforcerContext, "user:1", "team:2", "plan:3", "coupon", "create")
		require.NoError(t, err)
		require.False(t, r)

		r, err = authEnforcer.Enforce(enforcerContext, "user:1", "team:2", "plan:3", "tip", "delete")
		require.NoError(t, err)
		require.False(t, r)
	})
}
