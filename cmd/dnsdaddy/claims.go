package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/productclaims"
)

func runClaims(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: dnsdaddy claims check|export [-root DIR]")
	}
	cmd := args[0]
	fs := newFlagSet("claims " + cmd)
	root := fs.String("root", "", "repository root (default: discover from working directory)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	repoRoot := *root
	if repoRoot == "" {
		var err error
		repoRoot, err = productclaims.FindRepoRoot(".")
		if err != nil {
			return err
		}
	}
	switch cmd {
	case "check":
		if err := productclaims.Check(repoRoot); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "product claims inventory and generated artefacts are current")
		return nil
	case "export":
		inv, err := productclaims.Load(filepath.Join(repoRoot, productclaims.InventoryFile))
		if err != nil {
			return err
		}
		return productclaims.Export(repoRoot, inv, time.Now().UTC(), os.Stdout)
	default:
		return fmt.Errorf("unknown claims command %q (want check or export)", cmd)
	}
}
