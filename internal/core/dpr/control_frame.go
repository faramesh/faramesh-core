package dpr

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"time"
)

const (
	walVersionControl = byte(2)

	FrameKindBudgetUpdate = "BUDGET_UPDATE"
	FrameKindRateUpdate   = "RATE_UPDATE"
)

// ControlFrame is a non-DPR WAL entry for durable budget/rate state (FARAMESH.md §8).
type ControlFrame struct {
	FrameKind  string    `json:"frame_kind"`
	AgentID    string    `json:"agent_id"`
	Scope      string    `json:"scope,omitempty"`
	Tool       string    `json:"tool,omitempty"`
	SpentUSD   float64   `json:"spent_usd,omitempty"`
	CeilingUSD float64   `json:"ceiling_usd,omitempty"`
	Count      int64     `json:"count,omitempty"`
	Limit      int64     `json:"limit,omitempty"`
	Window     string    `json:"window,omitempty"`
	WrittenAt  time.Time `json:"written_at"`
}

// WriteControl appends a version-2 control frame to the WAL.
func (w *WAL) WriteControl(frame *ControlFrame) error {
	if frame == nil {
		return fmt.Errorf("nil control frame")
	}
	if frame.WrittenAt.IsZero() {
		frame.WrittenAt = time.Now().UTC()
	}
	return w.writeRawFrame(walVersionControl, frame)
}

func (w *WAL) writeRawFrame(version byte, payload any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return writeRawFrameFile(w.file, version, payload)
}

func writeRawFrameFile(f *os.File, version byte, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}
	var hdr [walHeaderSize]byte
	binary.LittleEndian.PutUint32(hdr[0:4], walFrameMagic)
	hdr[4] = version
	binary.LittleEndian.PutUint32(hdr[5:9], uint32(len(body)))
	binary.LittleEndian.PutUint32(hdr[9:13], crc32.ChecksumIEEE(body))
	if _, err := f.Write(hdr[:]); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if _, err := f.Write(body); err != nil {
		return fmt.Errorf("write frame payload: %w", err)
	}
	return f.Sync()
}

// ReplayControl replays version-2 control frames in order.
func (w *WAL) ReplayControl(fn func(*ControlFrame) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	for {
		version, payload, err := readNextFramePayload(w.file)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if version != walVersionControl {
			continue
		}
		var frame ControlFrame
		if err := json.Unmarshal(payload, &frame); err != nil {
			return fmt.Errorf("decode control frame: %w", err)
		}
		if err := fn(&frame); err != nil {
			return err
		}
	}
	_, _ = w.file.Seek(0, io.SeekEnd)
	return nil
}

// readNextFramePayload reads one WAL frame and returns its version and payload bytes.
func readNextFramePayload(r io.Reader) (byte, []byte, error) {
	var hdr [walHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return 0, nil, io.EOF
		}
		return 0, nil, fmt.Errorf("read WAL header: %w", err)
	}
	magic := binary.LittleEndian.Uint32(hdr[0:4])
	if magic != walFrameMagic {
		return 0, nil, fmt.Errorf("invalid WAL frame magic")
	}
	version := hdr[4]
	if version != walVersion && version != walVersionControl {
		return 0, nil, fmt.Errorf("%w: %d", errUnknownWALVersion, version)
	}
	n := binary.LittleEndian.Uint32(hdr[5:9])
	wantCRC := binary.LittleEndian.Uint32(hdr[9:13])
	if n == 0 || n > 8*1024*1024 {
		return 0, nil, fmt.Errorf("invalid WAL frame size %d", n)
	}
	payload := make([]byte, int(n))
	if _, err := io.ReadFull(r, payload); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return 0, nil, fmt.Errorf("truncated WAL payload")
		}
		return 0, nil, fmt.Errorf("read WAL payload: %w", err)
	}
	if crc32.ChecksumIEEE(payload) != wantCRC {
		return 0, nil, fmt.Errorf("WAL CRC mismatch")
	}
	return version, payload, nil
}
