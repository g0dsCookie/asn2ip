package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/g0dsCookie/asn2ip/internal/config"
	"github.com/g0dsCookie/asn2ip/pkg/asn2ip"
	"github.com/g0dsCookie/asn2ip/pkg/storage"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var (
	Version  string
	Revision string
)

func main() {
	app := cli.App{
		Name:    "asn2ip",
		Version: fmt.Sprintf("%s (build %s)", Version, Revision),
		Authors: []*cli.Author{
			{
				Name:  "g0dsCookie",
				Email: "asn2ip@copr.icu",
			},
		},
		Copyright: "(c) 2021 g0dsCookie",
		Usage:     "Map AS Numbers to IP Addresses",
		Commands: []*cli.Command{
			{
				Name:    "run",
				Aliases: []string{"daemon", "r", "d"},
				Usage:   "run asn2ip as http daemon",
				Flags:   append(config.CLIDaemonFlags, config.CLIStorageFlags...),
				Action:  runHandler,
			},
			{
				Name:    "fetch",
				Aliases: []string{"get", "g", "f"},
				Usage:   "fetch specified AS number(s) and exit",
				Action:  fetchHandler,
			},
		},
		Flags: config.CLIFlags,
	}
	app.Run(os.Args)
}

func setupLogging(format string, level int) {
	fields := logrus.Fields{"format": format}

	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.Level(level))

	switch format {
	case "plain":
		logrus.SetFormatter(&logrus.TextFormatter{})
	case "json":
		logrus.SetFormatter(&logrus.JSONFormatter{})
	default:
		logrus.WithFields(fields).Panicln("unknown log-format")
	}
}

func setup(c *cli.Context) *config.Config {
	conf := config.NewConfig()
	conf.UpdateFromCLIContext(c)
	setupLogging(conf.GetString("log.format"), conf.GetInt("log.level"))
	logrus.Info("loaded config and set up logging")
	return conf
}

func runHandler(c *cli.Context) error {
	conf := setup(c)
	daemon := config.NewDaemonConfig()
	daemon.UpdateFromCLIContext(c)
	stor := config.NewStorageConfig()
	stor.UpdateFromCLIContext(c)

	router, err := newRouter(serverOptions{
		WhoisHost: conf.GetString("whois.host"),
		WhoisPort: conf.GetInt("whois.port"),
		Storage: storage.StorageOptions{
			Name: stor.GetString("storage.name"),
			TTL:  stor.GetDuration("storage.ttl"),
		},
	})

	if err != nil {
		logrus.WithFields(logrus.Fields{"error": err}).Panicln("failed to initialize http router")
	}

	router.Run(fmt.Sprintf("%s:%d", daemon.GetString("listen.address"), daemon.GetInt("listen.port")))
	return nil
}

func fetchHandler(c *cli.Context) error {
	conf := setup(c)
	fetch := config.NewFetchConfig()
	fetch.UpdateFromCLIContext(c)

	fetcher := asn2ip.NewFetcher(conf.GetString("whois.host"), conf.GetInt("whois.port"))
	ips, err := fetcher.Fetch(fetch.GetBool("fetch.ipv4"), fetch.GetBool("fetch.ipv6"), c.Args().Slice()...)
	if err != nil {
		logrus.WithFields(logrus.Fields{"ipv4": fetch.GetBool("fetch.ipv4"), "ipv6": fetch.GetBool("fetch.ipv6"), "error": err}).Errorln("failed to fetch networks")
		return cli.Exit("", 10)
	}

	for as, ipversions := range ips {
		fmt.Printf("AS%s\n", as)
		for _, net := range ipversions {
			arr := make([]string, len(net))
			for k, v := range net {
				arr[k] = v.String()
			}
			fmt.Printf("  %s\n", strings.Join(arr, ","))
		}
	}

	return nil
}
