# Build stage
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-X main.version=${VERSION} -s -w" \
    -o /faramesh \
    ./cmd/faramesh

# Final image — distroless/static for minimal attack surface.
# The binary is ~28MB; the image is ~30MB total.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /faramesh /faramesh
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["/faramesh"]
CMD ["--help"]
