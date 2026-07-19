FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /dashboard-api .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /dashboard-api /usr/local/bin/dashboard-api
EXPOSE 8400
ENTRYPOINT ["dashboard-api"]
