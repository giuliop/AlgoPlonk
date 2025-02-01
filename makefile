.PHONY: test examples all

# The 'all' target runs examples first, then tests.
all: examples test

# Run tests only in packages that contain test files.
test:
	@echo "Running tests..."
	@go test -v $$(go list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' ./...)

# Run all example main.go files in the examples/ directory and its subdirectories.
examples:
	@echo "Running examples..."
	@find examples -name "main.go" | while read -r file; do \
		echo "Running $$file"; \
		go run "$$file"; \
	done
