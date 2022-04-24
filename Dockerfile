FROM golang:1.18-alpine

WORKDIR /app

COPY src/ ./
COPY .env ./

RUN go mod download

RUN go mod tidy

RUN go build -o /main

EXPOSE 8080

CMD [ "/main" ]