package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/faramesh/faramesh-core/internal/core/governance"
	"github.com/spf13/cobra"
)

var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Export an offline governance stack archive",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runBundle,
}

var bundleOutput string

func init() {
	bundleCmd.Flags().StringVarP(&bundleOutput, "output", "o", "governance-bundle.tar.gz", "output archive path")
}

func runBundle(_ *cobra.Command, args []string) error {
	stackDir, err := resolveStackDir()
	if err != nil {
		return err
	}
	if len(args) > 0 {
		stackDir = args[0]
	}
	out, err := os.Create(bundleOutput)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	add := func(name string) error {
		path := filepath.Join(stackDir, name)
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, name)
		if err != nil {
			return err
		}
		hdr.Name = name
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		f.Close()
		return err
	}
	for _, name := range []string{"governance.fms", "governance.fms.yaml", "governance.fms.json", "governance.compiled.json"} {
		if _, err := os.Stat(filepath.Join(stackDir, name)); err == nil {
			if err := add(name); err != nil {
				return err
			}
		}
	}
	fmt.Printf("wrote bundle %s from %s\n", bundleOutput, stackDir)
	_ = governance.CompiledPath(stackDir)
	return nil
}
