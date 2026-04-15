package dpr

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// WALFrameVersionStats summarizes on-disk frame version bytes without decoding JSON.
// Used for operator tooling and future format migrations.
type WALFrameVersionStats struct {
	Path            string
	FramesByVersion map[byte]uint64
	TotalFrames     uint64
	FileSize        int64
}

// ScanWALFrameVersions walks a WAL file and counts frames per header version byte.
// It does not validate DPR chains or JSON; it tolerates any version byte so operators
// can inspect files before upgrading readers.
func ScanWALFrameVersions(path string) (WALFrameVersionStats, error) {
	st := WALFrameVersionStats{
		Path:            path,
		FramesByVersion: make(map[byte]uint64),
	}
	fi, err := os.Stat(path)
	if err != nil {
		return st, err
	}
	st.FileSize = fi.Size()
	f, err := os.Open(path)
	if err != nil {
		return st, err
	}
	defer f.Close()

	for {
		var hdr [walHeaderSize]byte
		_, err := io.ReadFull(f, hdr[:])
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return st, fmt.Errorf("read WAL header: %w", err)
		}
		magic := binary.LittleEndian.Uint32(hdr[0:4])
		if magic != walFrameMagic {
			return st, fmt.Errorf("invalid WAL frame magic at offset (file may be corrupt)")
		}
		ver := hdr[4]
		n := binary.LittleEndian.Uint32(hdr[5:9])
		if n == 0 || n > 8*1024*1024 {
			return st, fmt.Errorf("invalid WAL frame size %d", n)
		}
		if _, err := f.Seek(int64(n), io.SeekCurrent); err != nil {
			return st, fmt.Errorf("skip payload: %w", err)
		}
		st.FramesByVersion[ver]++
		st.TotalFrames++
	}
	return st, nil
}
