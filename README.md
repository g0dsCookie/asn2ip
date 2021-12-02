# asn2ip

asn2ip is a helper tool to fetch all ip networks for specified AS numbers.

## Usage

### Single fetch

To simply fetch one or more AS numbers you can use the fetch command: `docker run ghcr.io/g0dscookie/asn2ip fetch 1234 2345`

### Daemon

asn2ip provides a simple built-in http server.

Simple run `docker run -p 8080:8080 ghcr.io/g0dscookie/asn2ip` to run the daemon.
You can then access the daemon with http://localhost:8080 or query AS numbers
with http://localhost:8080/1234

## Building

```
git clone https://github.com/g0dscookie/asn2ip.git
docker build --build-arg VERSION=1.0.0 --build-arg REVISION=$(git rev-list -1 HEAD) -t ghcr.io/g0dscookie/asn2ip .
```

Now simply run the tool with `docker run ghcr.io/g0dscookie/asn2ip`.