EXE := aws-runas
PKG := github.com/mmmorris1975/aws-runas
VER := $(shell git describe --tags)
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

$(EXE): Gopkg.lock *.go
	go build -v -o $@ $(PKG)

Gopkg.lock: Gopkg.toml
	dep ensure

.PHONY: release
release: $(EXE) darwin windows linux

.PHONY: darwin linux windows
darwin linux:
	GOOS=$@ go build -o $(EXE)-$(VER)-$@-$(GOARCH) $(PKG)
windows:
	GOOS=$@ go build -o $(EXE)-$(VER)-$@-$(GOARCH).exe $(PKG)

.PHONY: clean
clean:
	rm -f $(EXE) $(EXE)-*-*-*

.PHONY: dist-clean
dist-clean: clean
	rm -f Gopkg.lock
