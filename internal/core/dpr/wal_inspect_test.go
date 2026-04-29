package dpr

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestScanWALFrameVersions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.wal")
	w, err := OpenWAL(p)
	if err != nil {
		t.Fatal(err)
	}
	r1 := &Record{SchemaVersion: SchemaVersion, RecordID: "r1", AgentID: "a1", ToolID: "t1", CreatedAt: time.Now()}
	r2 := &Record{SchemaVersion: SchemaVersion, RecordID: "r2", AgentID: "a1", ToolID: "t2", CreatedAt: time.Now()}
	if err := w.Write(r1); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(r2); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := ScanWALFrameVersions(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.TotalFrames != 2 {
		t.Fatalf("total frames %d want 2", st.TotalFrames)
	}
	if st.FramesByVersion[walVersion] != 2 {
		t.Fatalf("version counts: %+v", st.FramesByVersion)
	}
	fi, _ := os.Stat(p)
	if st.FileSize != fi.Size() {
		t.Fatalf("file size %d vs stat %d", st.FileSize, fi.Size())
	}
}
