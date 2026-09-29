package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/protection"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func loadProtection(ctx context.Context, cfg config.Config, st *store.Store) (*protection.Controller, error) {
	settings := cfg.Protection
	raw, err := st.GetSetting(ctx, protection.SettingKey)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal([]byte(raw), &settings); err != nil {
			return nil, fmt.Errorf("read saved protection settings: %w", err)
		}
	}
	return protection.New(settings, func(ctx context.Context, next protection.Config) error {
		data, err := json.Marshal(next)
		if err != nil {
			return err
		}
		return st.SetSetting(ctx, protection.SettingKey, string(data))
	})
}
