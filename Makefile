MUXER_DIR := $(HOME)/.dotnet-muxer

.PHONY: all clean install uninstall

all:
	cargo build --release

clean:
	cargo clean

install: all
	@mkdir -p $(MUXER_DIR)
	cp target/release/dotnet $(MUXER_DIR)/dotnet
	@echo "Installed to $(MUXER_DIR)/dotnet"
	@echo "Make sure $(MUXER_DIR) is early in your PATH"

uninstall:
	rm -f $(MUXER_DIR)/dotnet $(MUXER_DIR)/log.log
