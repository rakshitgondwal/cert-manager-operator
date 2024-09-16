# Build the manager binary
FROM golang:1.23.0-alpine3.19 AS builder
ENV CGO_ENABLED=0
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app
# Copy the Go Modules manifests
COPY go.mod go.sum ./
# Download dependencies
RUN go mod download
# Copy the go source
COPY cmd/main.go cmd/main.go
COPY api/ api/
COPY internal/controller/ internal/controller/

# Build
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager cmd/main.go

# Runtime Image
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /app/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
