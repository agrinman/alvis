GODEBUG := cgocheck=0
export GODEBUG

@echo @GODEBUG
build:
	go build

install:
	go install

.PHONY: build install
