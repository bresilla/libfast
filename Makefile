.PHONY: build test ci install

build:
	zig build -Doptimize=ReleaseFast

test:
	zig build test --summary all

ci:
	zig build test --summary all
	zig build -Doptimize=ReleaseFast

install: build
	install -Dm644 "./zig-out/lib/libfast.a" "$(HOME)/.local/lib/libfast.a"

# Release
# ==================================================================================================
TYPE ?= patch
HAS_REL := $(shell command -v git-rel 2>/dev/null)

release:
	@if [ -z "$(HAS_REL)" ]; then \
		echo "git-rel is not installed. Please install it first."; \
		exit 1; \
	fi
	@if [ -z "$(TYPE)" ]; then \
		echo "Release type not specified. Use 'make release TYPE=[patch|minor|major|m.m.p]'"; \
		exit 1; \
	fi
	@git rel $(TYPE)
