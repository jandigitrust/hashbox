.PHONY: help setup image validate-vhd

help:
	@printf '%s\n' 'Set up local CLI: make setup' 'CLI help: .venv/bin/hashbox --help' 'Azure run: .venv/bin/hashbox run --profile dev' 'Builder image primitive: make image (on the builder)' 'VHD validation: make validate-vhd'

setup:
	./bin/setup-venv

image:
	sh ./toolchain/builder/build-attestor.sh
	./toolchain/release/build.sh

validate-vhd:
	./toolchain/disk/validate-vhd.sh
