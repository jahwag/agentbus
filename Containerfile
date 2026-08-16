FROM docker.io/library/golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS build
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid= -X github.com/jahwag/agentbus/internal/buildinfo.Version=${VERSION} -X github.com/jahwag/agentbus/internal/buildinfo.Revision=${REVISION} -X github.com/jahwag/agentbus/internal/buildinfo.Date=${CREATED}" -o /out/agentbusd ./cmd/agentbusd \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid= -X github.com/jahwag/agentbus/internal/buildinfo.Version=${VERSION} -X github.com/jahwag/agentbus/internal/buildinfo.Revision=${REVISION} -X github.com/jahwag/agentbus/internal/buildinfo.Date=${CREATED}" -o /out/agentbus ./cmd/agentbus \
 && mkdir -m 0700 /out/data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title='AgentBus' \
      org.opencontainers.image.description='Durable agent-to-agent messaging for small coding-agent fleets.' \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source='https://github.com/jahwag/agentbus' \
      org.opencontainers.image.licenses='MIT'
COPY --from=build /out/agentbusd /usr/local/bin/agentbusd
COPY --from=build /out/agentbus /usr/local/bin/agentbus
COPY --from=build --chown=nonroot:nonroot /out/data /var/lib/agentbus
USER nonroot:nonroot
VOLUME ["/var/lib/agentbus"]
ENTRYPOINT ["/usr/local/bin/agentbusd"]
CMD ["--listen=127.0.0.1:7777", "--db=/var/lib/agentbus/bus.db", "--admin-token-file=/run/secrets/admin-token"]
