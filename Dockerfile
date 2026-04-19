FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/certd          ./cmd/certd
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/certctl        ./cmd/certctl
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/certchain-sync ./cmd/certchain-sync

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /bin/certd          /usr/local/bin/certd
COPY --from=builder /bin/certctl        /usr/local/bin/certctl
COPY --from=builder /bin/certchain-sync /usr/local/bin/certchain-sync
VOLUME ["/data/certchain"]
EXPOSE 9879/tcp
EXPOSE 9878/tcp
EXPOSE 9876/udp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/certd"]
CMD ["--config", "/data/certchain"]
