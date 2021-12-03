package main

import (
	_ "embed"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/g0dsCookie/asn2ip/pkg/asn2ip"
	"github.com/g0dsCookie/asn2ip/pkg/storage"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

//go:embed index.html
var index string

type serverOptions struct {
	WhoisHost string
	WhoisPort int
	Url       string
	Storage   storage.StorageOptions
}

type router struct {
	fetcher asn2ip.Fetcher
	*gin.Engine
}

func newRouter(opts serverOptions) (*router, error) {
	stor, err := storage.NewStorage(opts.Storage)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize storage")
	}

	router := &router{
		fetcher: asn2ip.NewCachedFetcher(opts.WhoisHost, opts.WhoisPort, stor),
	}

	gin.SetMode(gin.ReleaseMode)

	engine := gin.New()
	router.Engine = engine
	engine.SetHTMLTemplate(template.Must(template.New("index").Parse(index)))
	engine.Use(requestLogger)
	engine.Use(gin.Recovery())

	engine.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index", gin.H{"BASE_URL": opts.Url})
	})
	engine.GET("/:asn", func(c *gin.Context) {
		asn := strings.Split(c.Param("asn"), ":")

		ipv4, err := strconv.ParseBool(c.DefaultQuery("ipv4", "true"))
		if err != nil {
			c.String(http.StatusBadRequest, "ipv4 query parameter must be a boolean")
			return
		}
		ipv6, err := strconv.ParseBool(c.DefaultQuery("ipv6", "true"))
		if err != nil {
			c.String(http.StatusBadRequest, "ipv6 query parameter must be a boolean")
			return
		}
		separator := c.DefaultQuery("separator", " ")
		json := wantJson(c)

		ips, err := router.fetcher.Fetch(ipv4, ipv6, asn...)
		if err != nil {
			c.String(http.StatusInternalServerError, "failed to fetch ip addresses for AS %s", strings.Join(asn, ":"))
			return
		}

		if json {
			normalized := map[string]map[string][]string{}
			for as, ipversions := range ips {
				normalized[as] = map[string][]string{}
				for ver, nets := range ipversions {
					normalizedNets := make([]string, len(nets))
					for i, net := range nets {
						normalizedNets[i] = net.String()
					}
					normalized[as][ver] = normalizedNets
				}
			}
			c.JSON(http.StatusOK, normalized)
		} else {
			allIP4, allIP6 := []string{}, []string{}
			for _, ipversions := range ips {
				for ver, nets := range ipversions {
					for _, net := range nets {
						if ver == "ipv4" {
							allIP4 = append(allIP4, net.String())
						} else if ver == "ipv6" {
							allIP6 = append(allIP6, net.String())
						}
					}
				}
			}
			c.String(http.StatusOK, strings.Join(append(allIP4, allIP6...), separator))
		}
	})

	return router, nil
}

func wantJson(c *gin.Context) bool {
	accept := c.GetHeader("Accept")
	return strings.EqualFold(accept, "application/json")
}

func requestLogger(c *gin.Context) {
	// start timer
	start := time.Now()
	path := c.Request.URL.Path
	query := c.Request.URL.RawQuery

	// process request
	c.Next()

	end := time.Now()

	if path != "" {
		path = path + "?" + query
	}

	param := logrus.Fields{
		"TimeStamp":    end,
		"Latency":      end.Sub(start),
		"ClientIP":     c.ClientIP(),
		"Method":       c.Request.Method,
		"StatusCode":   c.Writer.Status(),
		"ErrorMessage": c.Errors.ByType(gin.ErrorTypePrivate).String(),
		"BodySize":     c.Writer.Size(),
		"Path":         path,
	}
	logrus.WithFields(param).Info("processed http request")
}
