.PHONY: test examples all

# The 'all' target runs examples first, then tests.
all: examples test

# Run all tests.
test:
	@echo "Running tests..."
	@mkdir -p ./testutils/generated
	@rm -f ./testutils/generated/*
	@go test -v ./...

# Run all example main.go files in the examples/ directory and its subdirectories.
examples:
	@echo "Running examples..."
	@mkdir -p ./generated
	@rm -f ./generated/*
	@find examples -name "main.go" | while read -r file; do \
		echo "Running $$file"; \
		go run "$$file"; \
	done
