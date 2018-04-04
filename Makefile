EXE  := aws-runas
PKG  := github.com/mmmorris1975/aws-runas
VER  := $(shell git describe --tags)
PATH := build:$(PATH)
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

$(EXE): Gopkg.lock *.go lib/*.go
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

.PHONY: test
test: $(EXE)
	mv $(EXE) build
	go test -v ./...
	AWS_CONFIG_FILE=.aws/config AWS_PROFILE=arn:aws:iam::686784119290:role/circleci-role AWS_DEFAULT_PROFILE=circleci bundle exec rspec
