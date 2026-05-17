package provider

// Spec describes a declared governance provider block.
type Spec struct {
	Name   string
	Type   string
	Source string
	Config map[string]string
}
