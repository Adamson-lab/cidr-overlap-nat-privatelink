SHELL := /bin/bash
COMPOSE_FILE := deploy/docker-compose.yml

.PHONY: up down run test chaos bench lint

up:
	docker compose -f $(COMPOSE_FILE) up -d --wait

down:
	docker compose -f $(COMPOSE_FILE) down -v

lint:
	python3 -m py_compile controlplane/ipam_lease.py controlplane/server.py dataplane/resolver.py storage/audit_ledger.py tests/test_overlap.py

run:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	OPA_URL=http://localhost:8181 \
	OVERLAP_AUDIT_BUCKET=cidr-overlap-resolution-audit \
	WEBHOOK_HMAC_SECRET=local-dev-cidr-secret \
	uvicorn controlplane.server:app --host 0.0.0.0 --port 8080

test:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	OPA_URL=http://localhost:8181 \
	OVERLAP_AUDIT_BUCKET=cidr-overlap-resolution-audit \
	WEBHOOK_HMAC_SECRET=local-dev-cidr-secret \
	python3 -m unittest discover -s tests -p "test_*.py" -v

chaos:
	python3 -m unittest tests/test_overlap.py -k test_chaos_stale_token_rejected_after_takeover -v

bench:
	python3 -m unittest tests/test_overlap.py -k test_bench_lease_and_ledger -v
