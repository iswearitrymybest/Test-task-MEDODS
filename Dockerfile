FROM golang:1.23-bookworm AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o main ./cmd/...


FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends libx11-6 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /
COPY --from=builder /app/main .
EXPOSE 9000
CMD ["./main"]
