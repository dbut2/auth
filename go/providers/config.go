package providers

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Providers map[string]ProviderConfig `yaml:",inline"`
}

func init() {
	registerConfig[facebookConfig]("facebook")
	registerConfig[githubConfig]("github")
	registerConfig[googleConfig]("google")
	registerConfig[mockConfig]("mock-provider")
}

func registerConfig[T ProviderConfig](name string) {
	providerConfigs[name] = decode[T](name)
}

var providerConfigs = make(map[string]func(*yaml.Node) (ProviderConfig, error))

func decode[T ProviderConfig](name string) func(node *yaml.Node) (ProviderConfig, error) {
	return func(node *yaml.Node) (ProviderConfig, error) {
		aux := make(map[string]T)
		if err := node.Decode(&aux); err != nil {
			return nil, err
		}
		return aux[name], nil
	}
}

func (c *Config) UnmarshalYAML(node *yaml.Node) error {
	var aux map[string]any
	if err := node.Decode(&aux); err != nil {
		return err
	}
	c.Providers = make(map[string]ProviderConfig)
	for name := range aux {
		pcBuilder, ok := providerConfigs[name]
		if !ok {
			return fmt.Errorf("unknown config type: %s", name)
		}
		pc, err := pcBuilder(node)
		if err != nil {
			return err
		}
		c.Providers[name] = pc
	}
	return nil
}
