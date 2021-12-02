package asn2ip

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Fetcher struct {
	host string
	port int
}

func NewFetcher(host string, port int) *Fetcher {
	return &Fetcher{
		host: host,
		port: port,
	}
}

func readLine(conn net.Conn) (string, error) {
	resp := bytes.Buffer{}
	buf := make([]byte, 1)
	for {
		if _, err := conn.Read(buf[:1]); err != nil {
			return "", errors.Wrap(err, "failed to read next byte from connection")
		}
		if buf[0] == '\n' {
			break
		} else {
			if _, err := resp.Write(buf); err != nil {
				return "", errors.Wrap(err, "failed to write received byte to buffer")
			}
		}
	}
	return strings.TrimRight(resp.String(), "\r"), nil
}

func fetch(conn net.Conn, as string, version int) ([]*net.IPNet, error) {
	cmd := ""
	if version == 4 {
		cmd = fmt.Sprintf("!gAS%s\n", as)
	} else if version == 6 {
		cmd = fmt.Sprintf("!6AS%s\n", as)
	} else {
		return nil, errors.Errorf("unknown ip protocol version %d", version)
	}

	logrus.WithFields(logrus.Fields{"remote": conn.RemoteAddr(), "as": as, "version": version, "cmd": cmd}).Debugln("issuing fetch command")
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return nil, errors.Wrapf(err, "failed to fetch ip addresses for %s", as)
	}

	response := []*net.IPNet{}
	state := "start"
	for {
		line, err := readLine(conn)
		if err != nil {
			panic(err) // TODO
		}

		if line == "D" {
			return nil, errors.Errorf("as %s not found", as)
		} else if line == "C" {
			return response, nil
		}

		if state == "start" {
			if len(line) <= 0 {
				return nil, errors.Errorf("empty response for as %s", as)
			}
			if line[0] != 'A' {
				return nil, errors.Errorf("received invalid response for as %s", as)
			}
			state = "response"
			continue
		} else if state == "response" {
			nets := strings.Split(line, " ")
			for _, n := range nets {
				_, net, err := net.ParseCIDR(n)
				if err != nil {
					return nil, errors.Errorf("failed to parse network %s for as %s", n, as)
				}
				response = append(response, net)
			}
		}
	}
}

func (f *Fetcher) Fetch(ipv4, ipv6 bool, asn ...string) (map[string]map[string][]*net.IPNet, error) {
	result := map[string]map[string][]*net.IPNet{}
	if len(asn) == 0 {
		return result, nil
	}

	logrus.WithFields(logrus.Fields{"host": f.host, "port": f.port}).Debugln("connecting to whois host")
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", f.host, f.port))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to %s:%d", f.host, f.port)
	}
	defer func() {
		logrus.WithFields(logrus.Fields{"host": f.host, "port": f.port}).Debugln("closing socket to whois host")
		// gracefully close socket
		conn.Write([]byte("exit\n"))
		conn.Close()
	}()

	logrus.WithFields(logrus.Fields{"host": f.host, "port": f.port}).Debugln("enabling multicommand mode")
	// enable multiple commands per connection
	if _, err := conn.Write([]byte("!!\n")); err != nil {
		return nil, errors.Wrapf(err, "failed to enable multicommand mode")
	}

	for _, v := range asn {
		result[v] = map[string][]*net.IPNet{"ipv4": {}, "ipv6": {}}
		if ipv4 {
			net, err := fetch(conn, v, 4)
			if err != nil {
				return nil, err
			}
			result[v]["ipv4"] = net
		}
		if ipv6 {
			net, err := fetch(conn, v, 6)
			if err != nil {
				return nil, err
			}
			result[v]["ipv6"] = net
		}
	}

	return result, nil
}
