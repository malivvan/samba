# Static binary in a scratch image. Build with podman or docker:
#   CGO_ENABLED=0 go build -trimpath -o samba ./cmd/samba
#   podman build -t samba -f Containerfile .
# Or let the image build itself:
#   podman build -t samba -f Containerfile --build-arg BUILD=1 .
#
# The image reads its config from /etc/samba/samba.toml, so mount that and the
# share directories in, and publish port 445.
ARG BUILD=0
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/samba ./cmd/samba

FROM scratch
COPY --from=build /out/samba /usr/bin/samba
EXPOSE 445
ENTRYPOINT ["/usr/bin/samba", "--config", "/etc/samba/samba.toml"]
