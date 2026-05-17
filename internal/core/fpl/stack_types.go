package fpl

// ConfigValue is a scalar in runtime, provider, or identity blocks.
type ConfigValue struct {
	Kind ConfigValueKind

	String string
	Number float64
	Bool   bool
	EnvVar string
}

type ConfigValueKind string

const (
	ConfigString ConfigValueKind = "string"
	ConfigNumber ConfigValueKind = "number"
	ConfigBool   ConfigValueKind = "bool"
	ConfigEnv    ConfigValueKind = "env"
	ConfigIdent  ConfigValueKind = "ident"
)

type ImportDecl struct {
	Ref   string
	Alias string
	Line  int
}

type RuntimeBlock struct {
	Fields map[string]ConfigValue
}

type NamedProviderBlock struct {
	Name   string
	Fields map[string]ConfigValue
}

type NamedIdentityBlock struct {
	Name   string
	Fields map[string]ConfigValue
}

type TrustBlock struct {
	Raw []string
}
