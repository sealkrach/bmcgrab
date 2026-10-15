# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/bmcgrab ./cmd/bmcgrab

# distroless: no shell, no package manager, non-root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/bmcgrab /bmcgrab
USER nonroot:nonroot
VOLUME ["/var/lib/bmcgrab"]
EXPOSE 8080 9090
ENTRYPOINT ["/bmcgrab"]
CMD ["collector", "--config", "/etc/bmcgrab/config.yaml"]
