.PHONY: build test vet fuzz benchmark-m1 web-install web-build web-audit check

build:
	go build ./cmd/proxyloom

web-install:
	cd web && npm ci

web-build:
	cd web && npm run build

web-audit:
	cd web && npm audit --audit-level=high

test:
	go test ./...

vet:
	go vet ./...

fuzz:
	go test ./internal/jsonlossless -run '^$$' -fuzz '^FuzzParseRoundTrip$$' -fuzztime 10s

benchmark-m1:
	go test -run '^$$' -bench '20000' -benchtime=1x -benchmem ./internal/format/singbox ./internal/occurrence ./internal/naming

check: vet test
