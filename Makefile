MUXER_HOME := $(HOME)/.dotnet-muxer
EXT_DIR := vscode-extension
BIN_DIR := $(EXT_DIR)/bin

# Cross-compilation targets for the VSIX package
TARGETS := \
	aarch64-apple-darwin \
	x86_64-apple-darwin \
	aarch64-unknown-linux-gnu \
	x86_64-unknown-linux-gnu \
	x86_64-pc-windows-msvc

.PHONY: all clean install uninstall package

all:
	cargo build --release

clean:
	cargo clean
	rm -rf $(BIN_DIR)
	rm -f $(EXT_DIR)/*.vsix

install: all
	@mkdir -p $(MUXER_HOME)/dotnet $(MUXER_HOME)/workspaces
	cp target/release/dotnet $(MUXER_HOME)/dotnet/dotnet
	@echo "Installed to $(MUXER_HOME)/dotnet/dotnet"
	@echo "Make sure $(MUXER_HOME)/dotnet is early in your PATH"

uninstall:
	rm -rf $(MUXER_HOME)

# Build for all targets and package the VSIX
package:
	@mkdir -p $(BIN_DIR)
	@for target in $(TARGETS); do \
		echo "Building $$target..."; \
		if cargo build --release --target $$target 2>/dev/null; then \
			case $$target in \
				aarch64-apple-darwin) cp target/$$target/release/dotnet $(BIN_DIR)/dotnet-arm64-darwin ;; \
				x86_64-apple-darwin)  cp target/$$target/release/dotnet $(BIN_DIR)/dotnet-x64-darwin ;; \
				aarch64-unknown-linux-gnu) cp target/$$target/release/dotnet $(BIN_DIR)/dotnet-arm64-linux ;; \
				x86_64-unknown-linux-gnu)  cp target/$$target/release/dotnet $(BIN_DIR)/dotnet-x64-linux ;; \
				x86_64-pc-windows-msvc)    cp target/$$target/release/dotnet.exe $(BIN_DIR)/dotnet-x64-windows.exe ;; \
			esac; \
		else \
			echo "  Skipped $$target (toolchain not available)"; \
		fi; \
	done
	cd $(EXT_DIR) && npx --yes @vscode/vsce package --allow-missing-repository
	@echo "VSIX packaged in $(EXT_DIR)/"
