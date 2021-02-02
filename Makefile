SHELL := /bin/bash
EXE := aws-runas
VER := $(shell git describe --tags)
LDFLAGS := -ldflags '-s -w -X main.Version=$(VER)'
BUILDDIR := build
PKGDIR := pkg
PATH := $(BUILDDIR):$(PATH)
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

.PHONY: all darwin linux windows zip linux_pkg release clean dist-clean test docs

$(EXE): go.mod *.go **/*.go
	go build -v $(LDFLAGS)

all: darwin linux windows

# Apple M1 support coming in go 1.16, current arm64 support is only iOS
# See https://stackoverflow.com/questions/65706980/golang-1-16-cgo-clang-build-failed-on-darwin-arm64
# for explanation about compiler error for darwin/arm64 builds
darwin: GOOS = darwin
linux: GOOS = linux
windows: GOOS = windows

# Use .SECONDEXPANSION so we can expand target-specific vars in the prereq statement
.SECONDEXPANSION:
darwin linux: $$(BUILDDIR)/$$@/$$(GOARCH)/$$(EXE)
windows: $$(BUILDDIR)/$$@/$$(GOARCH)/$$(EXE).exe

# Don't use file-specific make target, .deb and .rpm file names can get goofy, just do the packaging here
# Local execution will use the same docker image used by the circleci job
linux_pkg: GOOS = linux
linux_pkg: $$(GOOS) $$(PKGDIR)/$$(EXE)-$(VER)-$$(GOOS)-$$(GOARCH).zip
	@if [ -z ${CIRCLECI} ]; then \
		docker run --rm -e VER=$(VER) -e ARCH=$(GOARCH) -v ${PWD}:/build --entrypoint /build/scripts/package.sh cimg/ruby:2.7; \
  	else \
  		ARCH=$(GOARCH) scripts/package.sh; \
  	fi;

zip: $$(GOOS) $$(PKGDIR)/$$(EXE)-$(VER)-$$(GOOS)-$$(GOARCH).zip

$(PKGDIR):
	mkdir -p $@

$(PKGDIR)/$(EXE)-%.zip: $(PKGDIR)
	zip -j $@ $(BUILDDIR)/$(GOOS)/$(GOARCH)/$(EXE)*

# Having $(GOARM) unset, with non-arm builds, doesn't seem to harm anything
# osslsigncode is available in cimg/ruby:2.7 and cimg/go:1.15 images
$(BUILDDIR)/%:
	mkdir -p $(@D)
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) go build $(LDFLAGS) -o $(@D)/
	upx -v $@

	@if [ $(GOOS) == "windows" ]; then \
  		mkdir -p .ca; \
		out=$(@D)/$(EXE)-signed.exe; \
		set -x; \
		osslsigncode sign -certs .ca/codesign.crt -key .ca/codesign.key -n $(EXE) -i https://github.com/mmmorris1975/aws-runas -in $@ -out $$out; \
		mv $$out $@; \
	fi;

release: $(EXE) darwin windows linux
	docker run --rm -e VER=$(VER) -v ${PWD}:/build --entrypoint /build/scripts/package.sh debian:stretch

clean:
	rm -f $(EXE) $(EXE)-*-*-* $(EXE)*.rpm $(EXE)*.deb $(EXE)*.exe
	rm -rf $(BUILDDIR)/* $(PKGDIR)/*

distclean: clean
	rm -f go.sum

test: $(EXE)
	mv $(EXE) $(BUILDDIR)
	go test -race -count 1 -v ./...
	bundle install
	AWS_CONFIG_FILE=.aws/config AWS_PROFILE=arn:aws:iam::686784119290:role/circleci-role AWS_DEFAULT_PROFILE=circleci bundle exec rspec

docs:
	cd docs && bundle install
	cd docs && bundle exec jekyll build
	cd docs && bundle exec jekyll serve
