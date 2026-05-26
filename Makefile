all: test

test:
	go test -v -race ./...

coverage:
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

lint:
	golangci-lint run .
