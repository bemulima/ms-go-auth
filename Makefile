MIGRATE_BIN := $(shell go env GOPATH)/bin/migrate

run:
	go run ./cmd/ms-go-auth

test:
	go test ./...

migrate-up:
	@echo "Running migration up..."
	@if [ "$$AUTH_DB_HOST" = "postgres" ]; then \
		echo "Note: AUTH_DB_HOST is 'postgres' (Docker hostname). Trying localhost..."; \
		$(MIGRATE_BIN) -path ./migrations -database "postgres://$$AUTH_DB_USER:$$AUTH_DB_PASSWORD@localhost:$$AUTH_DB_PORT/$$AUTH_DB_NAME?sslmode=$$AUTH_DB_SSLMODE" up || \
		echo "Failed to connect to localhost. If using Docker, run: docker compose exec postgres psql -U $$AUTH_DB_USER -d $$AUTH_DB_NAME -f /path/to/migrations/0002_seed_auth_users.up.sql"; \
	else \
		$(MIGRATE_BIN) -path ./migrations -database "postgres://$$AUTH_DB_USER:$$AUTH_DB_PASSWORD@$$AUTH_DB_HOST:$$AUTH_DB_PORT/$$AUTH_DB_NAME?sslmode=$$AUTH_DB_SSLMODE" up; \
	fi

migrate-down:
	@echo "Running migration down..."
	@if [ "$$AUTH_DB_HOST" = "postgres" ]; then \
		echo "Note: AUTH_DB_HOST is 'postgres' (Docker hostname). Trying localhost..."; \
		$(MIGRATE_BIN) -path ./migrations -database "postgres://$$AUTH_DB_USER:$$AUTH_DB_PASSWORD@localhost:$$AUTH_DB_PORT/$$AUTH_DB_NAME?sslmode=$$AUTH_DB_SSLMODE" down || \
		echo "Failed to connect to localhost. If using Docker, run: docker compose exec postgres psql -U $$AUTH_DB_USER -d $$AUTH_DB_NAME"; \
	else \
		$(MIGRATE_BIN) -path ./migrations -database "postgres://$$AUTH_DB_USER:$$AUTH_DB_PASSWORD@$$AUTH_DB_HOST:$$AUTH_DB_PORT/$$AUTH_DB_NAME?sslmode=$$AUTH_DB_SSLMODE" down; \
	fi
