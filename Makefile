run:
	go run ./cmd/ms-go-auth

test:
	go test ./...

migrate-up:
	task migrate-up

migrate-status:
	task migrate-status

migrate-down:
	task migrate-down
