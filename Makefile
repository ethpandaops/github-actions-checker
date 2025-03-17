.PHONY: build clean test docker

BINARY_NAME=action-deps
GO=go

build:
	$(GO) build -o $(BINARY_NAME)

run-org: build
	./$(BINARY_NAME) --org $(ORG)

run-repo: build
	./$(BINARY_NAME) --repo $(REPO)

clean:
	rm -f $(BINARY_NAME)
	$(GO) clean

test:
	$(GO) test ./... -v

install:
	$(GO) install

lint:
	golangci-lint run

docker:
	docker build -t $(BINARY_NAME) .

.DEFAULT_GOAL := build
