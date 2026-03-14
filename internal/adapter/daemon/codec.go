package daemon

import "encoding/json"

// jsonCodec allows this gRPC service to transport plain Go structs.
// We intentionally use this for the handwritten daemon service types.
type jsonCodec struct{}

func (jsonCodec) Name() string { return "json" }

func (jsonCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
