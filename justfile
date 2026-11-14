# Development tasks for open-nexus. Run `just` to list them.

# List the available recipes
default:
    @just --list

# Format the code
fmt:
    cargo fmt --all

# Check formatting without changing files
fmt-check:
    cargo fmt --all --check

# Run clippy on every target; warnings are errors
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Run the tests
test:
    cargo test --workspace

# Everything a commit must pass: formatting, lints and tests
check: fmt-check lint test
