# Build stage: compile the Go binary
FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod .
COPY main.go .
RUN go build -ldflags="-s -w" -o firewall .

# Runtime stage: minimal alpine with iptables/ip6tables available
FROM alpine:3.24
ARG VERSION
ENV VERSION=$VERSION

# iptables / ip6tables are needed at container runtime to apply rules
RUN apk add --no-cache iptables ip6tables

COPY --from=builder /build/firewall /usr/local/bin/firewall

CMD ["firewall"]
