#!/bin/bash

find . -name "main.go" | while read -r file; do
    echo "Running $file"
    go run "$file"
done
