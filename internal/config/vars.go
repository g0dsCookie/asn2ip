package config

import (
	"time"

	"github.com/urfave/cli/v2"
)

type (
	configVarType string
	configVar     struct {
		Type    configVarType
		Default interface{}
		CLIFlag cli.Flag
	}
)

var (
	CLIFlags        []cli.Flag
	CLIDaemonFlags  []cli.Flag
	CLIFetchFlags   []cli.Flag
	CLIStorageFlags []cli.Flag
)

var (
	stringType   configVarType = "string"
	intType      configVarType = "int"
	boolType     configVarType = "bool"
	durationType configVarType = "time.Duration"
)

var configVars = map[string]configVar{
	"debug": {
		Type:    boolType,
		Default: false,
		CLIFlag: &cli.BoolFlag{
			Name:    "debug",
			Usage:   "show debug messages",
			EnvVars: []string{"DEBUG"},
		},
	},
	"log.format": {
		Type:    stringType,
		Default: "plain",
		CLIFlag: &cli.StringFlag{
			Name:    "log-format",
			Usage:   "set log format (plain, json)",
			EnvVars: []string{"LOG_FORMAT"},
		},
	},
	"log.level": {
		Type:    intType,
		Default: 4,
		CLIFlag: &cli.IntFlag{
			Name:    "log-level",
			Usage:   "set log level from 0 (only highest severity) to 6 (only lowest severity)",
			EnvVars: []string{"LOG_LEVEL"},
		},
	},
	"whois.host": {
		Type:    stringType,
		Default: "whois.radb.net",
		CLIFlag: &cli.StringFlag{
			Name:    "whois-host",
			Usage:   "set whois host to request",
			EnvVars: []string{"WHOIS_HOST"},
		},
	},
	"whois.port": {
		Type:    intType,
		Default: 43,
		CLIFlag: &cli.IntFlag{
			Name:    "whois-port",
			Usage:   "set whois port to query",
			EnvVars: []string{"WHOIS_PORT"},
		},
	},
}

var daemonVars = map[string]configVar{
	"listen.address": {
		Type:    stringType,
		Default: "0.0.0.0",
		CLIFlag: &cli.StringFlag{
			Name:    "listen",
			Usage:   "set listen ip address",
			EnvVars: []string{"LISTEN_ADDRESS"},
		},
	},
	"listen.port": {
		Type:    intType,
		Default: 8080,
		CLIFlag: &cli.IntFlag{
			Name:    "port",
			Usage:   "set listen port",
			EnvVars: []string{"LISTEN_PORT"},
		},
	},
}

var fetchVars = map[string]configVar{
	"fetch.ipv4": {
		Type:    boolType,
		Default: true,
		CLIFlag: &cli.BoolFlag{
			Name:  "ipv4",
			Usage: "fetch ipv4 networks",
		},
	},
	"fetch.ipv6": {
		Type:    boolType,
		Default: true,
		CLIFlag: &cli.BoolFlag{
			Name:  "ipv6",
			Usage: "fetch ipv6 networks",
		},
	},
}

var storageVars = map[string]configVar{
	"storage.name": {
		Type:    stringType,
		Default: "",
		CLIFlag: &cli.StringFlag{
			Name:  "storage-name",
			Usage: "set storage backend to use",
		},
	},
	"storage.ttl": {
		Type:    durationType,
		Default: 86400 * time.Second,
		CLIFlag: &cli.DurationFlag{
			Name:  "storage-ttl",
			Usage: "set max ttl for cache",
		},
	},
}

func populateFlags(dest *[]cli.Flag, vars map[string]configVar) {
	*dest = []cli.Flag{}
	for _, c := range vars {
		if flag := c.CLIFlag; flag != nil {
			*dest = append(*dest, flag)
		}
	}
}

func init() {
	populateFlags(&CLIFlags, configVars)
	populateFlags(&CLIDaemonFlags, daemonVars)
	populateFlags(&CLIFetchFlags, fetchVars)
	populateFlags(&CLIStorageFlags, storageVars)
}
