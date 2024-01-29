FROM golang:alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY go/ html/ static/ ./
RUN go build -o /bin/server ./go

FROM alpine AS final

WORKDIR /app

COPY --from=builder /bin/server ./server

CMD ["./server"]