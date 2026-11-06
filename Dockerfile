# Multi-stage Dockerfile for s3web (Private VPC / ECS Fargate Deployment)
FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/s3web ./cmd/s3web

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /out/s3web /app/s3web

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/s3web"]

