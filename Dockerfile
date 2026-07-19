# syntax=docker/dockerfile:1
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS singbox

ARG TARGETARCH
ARG SING_BOX_12_VERSION=1.12.25
ARG SING_BOX_13_VERSION=1.13.14
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && case "$TARGETARCH" in \
         amd64) sha12=a1ec76e2b6b139eb747a1b1ebee7d14b8d4be5a833596cad8070a31ef960301f; \
                sha13=f48703461a15476951ac4967cdad339d986f4b8096b4eb3ff0829a500502d697 ;; \
         arm64) sha12=719b76196c8b31efa636b2d8f669e314547e0da0a5ab38a75e1882d307bbd154; \
                sha13=4742df6a4314e8ecc41736849fca6d73b8f9e91b6e8b06ee794ff17ba180579e ;; \
         *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
       esac \
    && for item in "${SING_BOX_12_VERSION}:${sha12}" "${SING_BOX_13_VERSION}:${sha13}"; do \
         version="${item%%:*}"; sha256="${item#*:}"; \
         archive="sing-box-${version}-linux-${TARGETARCH}.tar.gz"; \
         directory="/tmp/sing-box-${version}-linux-${TARGETARCH}"; \
         curl --proto '=https' --tlsv1.2 --retry 5 --retry-all-errors -fsSLo "/tmp/${archive}" \
           "https://github.com/SagerNet/sing-box/releases/download/v${version}/${archive}"; \
         echo "${sha256}  /tmp/${archive}" | sha256sum -c -; \
         tar -xzf "/tmp/${archive}" -C /tmp; \
         install -D -m 0755 "${directory}/sing-box" "/out/sing-box-${version}/sing-box"; \
         install -D -m 0644 "${directory}/LICENSE" "/out/sing-box-${version}/LICENSE"; \
         if [ -f "${directory}/libcronet.so" ]; then \
           install -D -m 0755 "${directory}/libcronet.so" "/out/sing-box-${version}/libcronet.so"; \
         fi; \
       done

FROM node:22.17.1-bookworm-slim@sha256:2fa754a9ba4d7adbd2a51d182eaabbe355c82b673624035a38c0d42b08724854 AS webbuild

WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.25.12-bookworm@sha256:ea341baa9bd5ba6784f6d7161ace70544349a6242d54d34a0fbfd2c4d51c9d58 AS build

ARG GOPROXY=https://goproxy.cn,direct
WORKDIR /src
COPY go.mod go.sum ./
RUN GOPROXY="${GOPROXY}" go mod download
COPY . .
COPY --from=webbuild /src/internal/webui/dist ./internal/webui/dist
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/proxyloom ./cmd/proxyloom

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:66aa873a4a14fb164aa01296058efd8253744606d72715e45acface073359faa

COPY --from=build /out/proxyloom /proxyloom
COPY --from=singbox /out/sing-box-1.12.25 /opt/sing-box-1.12.25
COPY --from=singbox /out/sing-box-1.13.14 /opt/sing-box-1.13.14
USER 65532:65532
EXPOSE 8080
VOLUME ["/var/lib/proxyloom"]
ENTRYPOINT ["/proxyloom"]
CMD ["serve"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/proxyloom", "healthcheck", "--url", "http://127.0.0.1:8080/readyz"]
