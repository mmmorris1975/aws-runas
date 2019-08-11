EXE  := aws-runas
VER  := $(shell git describe --tags)
PATH := build:$(PATH)
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

.PHONY: darwin linux windows release clean dist-clean test docs

$(EXE): go.mod *.go lib/*/*.go
	go build -v -ldflags '-X main.Version=$(VER)' -o $@

release: $(EXE) darwin windows linux
	docker run --rm -e VER=$(VER) -v ${PWD}:/build --entrypoint /build/scripts/package.sh debian:stretch

darwin linux:
	GOOS=$@ go build -ldflags '-X main.Version=$(VER)' -o $(EXE)-$(VER)-$@-$(GOARCH)

# $(shell go env GOEXE) is evaluated in the context of the Makefile host (before GOOS is evaluated), so hard-code .exe
windows:
	GOOS=$@ go build -ldflags '-X main.Version=$(VER)' -o $(EXE)-$(VER)-$@-$(GOARCH)-unsigned.exe
	osslsigncode sign -certs .ca/codesign.crt -key .ca/codesign.key -n "aws-runas" -i https://github.com/mmmorris1975/aws-runas -in $(EXE)-$(VER)-$@-$(GOARCH)-unsigned.exe -out $(EXE)-$(VER)-$@-$(GOARCH).exe
	rm -f $(EXE)-$(VER)-$@-$(GOARCH)-unsigned.exe

clean:
	rm -f $(EXE) $(EXE)-*-*-* $(EXE)*.rpm $(EXE)*.deb

dist-clean: clean
	rm -f go.sum

test: $(EXE)
	mv $(EXE) build
	go test -count 1 -v ./...
	bundle install
	AWS_CONFIG_FILE=.aws/config AWS_PROFILE=arn:aws:iam::686784119290:role/circleci-role AWS_DEFAULT_PROFILE=circleci bundle exec rspec

docs:
	cd docs && bundle install
	cd docs && bundle exec jekyll build
	cd docs && bundle exec jekyll serve
