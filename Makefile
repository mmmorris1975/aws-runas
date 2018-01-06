EXE := aws-runas
PKG := github.com/mmmorris1975/go-aws-runas
VER := $(shell git describe --tags)
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

$(EXE): Gopkg.toml *.go
	go build -v -o $@ $(PKG)

Gopkg.toml:
	dep ensure

.PHONY: release
release: darwin windows linux

.PHONY: darwin linux windows
darwin linux:
	GOOS=$@ go build -o $(EXE)-$(VER)-$@-$(GOARCH) $(PKG)
windows:
	GOOS=$@ go build -o $(EXE)-$(VER)-$@-$(GOARCH).exe $(PKG)

.PHONY: clean
clean:
	rm -f $(EXE) $(EXE)-*-*-*
