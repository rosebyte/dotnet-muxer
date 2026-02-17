PREFIX ?= $(HOME)/bin
TARGET := dotnet

.PHONY: all clean install uninstall

all:
	cargo build --release

clean:
	cargo clean

install: all
	@mkdir -p $(PREFIX)
	cp target/release/$(TARGET) $(PREFIX)/$(TARGET)
	@echo "Installed to $(PREFIX)/$(TARGET)"
	@echo "Make sure $(PREFIX) is early in your PATH"

uninstall:
	rm -f $(PREFIX)/$(TARGET)
