.PHONY: build install

build:
	zig build -Doptimize=ReleaseFast

install: build
	install -Dm644 "./zig-out/lib/libvoidbox.a" "$(HOME)/.local/lib/libvoidbox.a"
