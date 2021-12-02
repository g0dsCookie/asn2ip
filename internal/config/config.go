package config

import (
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
)

type Config struct {
	vars map[string]configVar
	*viper.Viper
}

func newConfig(name string, vars map[string]configVar) *Config {
	conf := &Config{
		vars:  vars,
		Viper: viper.New(),
	}
	conf.SetConfigName(name)
	conf.SetConfigType("yaml")
	conf.AddConfigPath("/etc/asn2ip")
	conf.AddConfigPath("$HOME/.config/asn2ip")
	conf.AddConfigPath("./configs")
	conf.AddConfigPath(".")
	conf.setDefaults()
	return conf
}

func NewConfig() *Config { return newConfig("asn2ip", configVars) }

func NewDaemonConfig() *Config { return newConfig("daemon", daemonVars) }

func NewFetchConfig() *Config { return newConfig("fetch", fetchVars) }

func (conf *Config) UpdateFromCLIContext(c *cli.Context) {
	for k, v := range conf.vars {
		if flag := v.CLIFlag; flag != nil {
			for _, name := range flag.Names() {
				if !c.IsSet(name) {
					continue
				}
				switch v.Type {
				case stringType:
					conf.Set(k, c.String(name))
				case intType:
					conf.Set(k, c.Int(name))
				case boolType:
					conf.Set(k, c.Bool(name))
				case durationType:
					conf.Set(k, c.Duration(name))
				}
			}
		}
	}
}

func (conf *Config) setDefaults() {
	for k, v := range conf.vars {
		conf.SetDefault(k, v.Default)
	}
}
