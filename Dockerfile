FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY . ./
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/pulse .

FROM alpine:3.21
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /out/pulse /usr/local/bin/pulse
ENV PULSE_ADDR=:8090
ENV USER_DATA_DIR=/data
EXPOSE 8090
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8090/health || exit 1
ENTRYPOINT ["pulse"]
CMD ["serve"]

