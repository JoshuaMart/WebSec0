# Helper Makefile for the legacy E2E fixture. Use from the parent
# directory: `make -C tests/e2e/legacy-fixture up`.
.PHONY: certs up down clean

CERT_CN ?= localhost

# Generate a self-signed cert valid for localhost. The fixture is meant
# to be probed via `localhost:18443` only, never exposed publicly.
certs: tls/fixture.crt

tls/fixture.crt:
	@mkdir -p tls
	openssl req -x509 -nodes -days 365 \
		-newkey rsa:2048 \
		-keyout tls/fixture.key \
		-out    tls/fixture.crt \
		-subj "/CN=$(CERT_CN)" \
		-addext "subjectAltName=DNS:localhost,DNS:127.0.0.1,IP:127.0.0.1"
	@chmod 644 tls/fixture.key

up: certs
	docker compose up -d --wait

down:
	docker compose down -v

clean: down
	rm -rf tls
