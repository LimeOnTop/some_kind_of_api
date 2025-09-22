FROM golang:1.24-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /bin/diary ./main.go

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=build /bin/diary /bin/diary
EXPOSE 8080
ENTRYPOINT ["/bin/diary"]
