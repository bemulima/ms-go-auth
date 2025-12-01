FROM golang:1.24-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git
COPY go.mod go.sum ./ 
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o ms-go-auth ./cmd/ms-go-auth

FROM alpine:3.19
RUN adduser -D -g '' appuser
WORKDIR /home/appuser
COPY --from=builder /app/ms-go-auth /usr/local/bin/ms-go-auth
EXPOSE 8081
USER appuser
ENTRYPOINT ["/usr/local/bin/ms-go-auth"]
