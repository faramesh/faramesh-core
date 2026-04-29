# Multi-stage build: single static faramesh binary (open faramesh-core module).
# Build: docker build -t faramesh:local -f Dockerfile .
# Run:  docker run --rm faramesh:local faramesh version

FROM golang:1.25-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=docker" -o /out/faramesh ./cmd/faramesh

FROM alpine:3.21
RUN apk add --no-cache ca-certificates && adduser -D -u 65532 nonroot
USER nonroot:nonroot
COPY --from=build /out/faramesh /usr/local/bin/faramesh
ENTRYPOINT ["/usr/local/bin/faramesh"]
