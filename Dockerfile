ARG GOVERSION=1.17
FROM golang:${GOVERSION} AS builder

COPY . /go/src/app/
WORKDIR /go/src/app

ARG VERSION
ARG REVISION

RUN set -eu \
 && go build -o /asn2ip -ldflags "-X main.Version=${VERSION} -X main.Revision=${REVISION}" ./cmd/asn2ip

ARG DEBIAN_VERSION=11
FROM gcr.io/google-appengine/debian${DEBIAN_VERSION}
COPY --from=builder --chown=root:root /asn2ip /asn2ip
USER nobody
EXPOSE 8080
ENTRYPOINT [ "/asn2ip" ]
CMD [ "run" ]