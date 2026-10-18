package api

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func TestF03PasswordSurvivesReopenWithRetainedBootstrap(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuth(st, dir, AuthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	const bootstrap = "synthetic-bootstrap-password"
	const rotated = "synthetic-replacement-password"
	if _, err = auth.EnsureAdminPassword(ctx, bootstrap, dir); err != nil {
		t.Fatal(err)
	}
	token, err := auth.Login(ctx, bootstrap, "synthetic-old-session")
	if err != nil {
		t.Fatal(err)
	}
	if err = auth.SetPassword(ctx, bootstrap, rotated); err != nil {
		t.Fatal(err)
	}
	want, err := st.GetSetting(ctx, settingAdminHash)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.Close(); err != nil {
		t.Fatal(err)
	}
	for _, configured := range []string{bootstrap, "", strings.Repeat("x", 73)} {
		st, err = store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		auth, err = NewAuth(st, dir, AuthOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = auth.EnsureAdminPassword(ctx, configured, dir); err != nil {
			t.Fatal("existing credential must ignore bootstrap input")
		}
		got, err := st.GetSetting(ctx, settingAdminHash)
		if err != nil || got != want {
			t.Fatal("restart replaced stored credential")
		}
		if live, e := st.LookupSession(ctx, token); e != nil || live {
			t.Fatal("pre-rotation session survived restart")
		}
		if !auth.CheckPassword(ctx, rotated) || auth.CheckPassword(ctx, bootstrap) {
			t.Fatal("rotation did not survive restart")
		}
		if err = st.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
