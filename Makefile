MUXER_DIR := $(HOME)/.dotnet-muxer

ifeq ($(OS),Windows_NT)
IS_WINDOWS := 1
POWERSHELL ?= powershell
else
IS_WINDOWS := 0
endif

.PHONY: all clean install uninstall

all:
	cargo build --release

clean:
	cargo clean

ifeq ($(IS_WINDOWS),1)

install: all
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1

uninstall:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File .\scripts\uninstall.ps1

else

install: all
	bash ./scripts/install.sh

uninstall:
	bash ./scripts/uninstall.sh

endif
