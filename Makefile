SHELL := /bin/bash
EXE := aws-runas
VER := $(shell git describe --tags)
LDFLAGS := -ldflags '-s -w -X main.Version=$(VER)'
BUILDDIR := build
PKGDIR := pkg
PATH := $(BUILDDIR):${GOROOT}/bin:${PATH}
GOOS ?= $(shell ${GOROOT}/bin/go env GOOS)
GOARCH ?= $(shell ${GOROOT}/bin/go env GOARCH)

.PHONY: all darwin linux windows zip linux_pkg release clean dist-clean test-setup gotest rspec test docs lint

$(EXE): go.mod *.go **/*.go
	go build -v $(LDFLAGS)

all: darwin linux windows

# Apple M1 support available in go 1.16, previously darwin/arm64 build target was for ios
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
		docker run --rm -e VER=$(VER) -e ARCH=$(GOARCH) -v $${PWD}:/build --user root --entrypoint /build/scripts/package.sh cimg/ruby:2.7; \
  	else \
  		ARCH=$(GOARCH) VER=$(VER) scripts/package.sh; \
  	fi;

zip: $$(GOOS) $$(PKGDIR)/$$(EXE)-$(VER)-$$(GOOS)-$$(GOARCH).zip

$(PKGDIR):
	mkdir -p $@

$(PKGDIR)/$(EXE)-%.zip: $(PKGDIR)
	zip -j $@ $(BUILDDIR)/$(GOOS)/$(GOARCH)/$(EXE)*

# Having $(GOARM) unset, with non-arm builds, doesn't seem to harm anything
# osslsigncode package is available in cimg/ruby:2.7 and cimg/go:1.15 images
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

#release: $(EXE) darwin windows linux
#	docker run --rm -e VER=$(VER) -v ${PWD}:/build --entrypoint /build/scripts/package.sh debian:stretch

lint:
	docker run --rm -v $${PWD}:/app -w /app -t golangci/golangci-lint:v1.41 golangci-lint run -v

clean:
	rm -f $(EXE) $(EXE)-*-*-* $(EXE)*.rpm $(EXE)*.deb $(EXE)*.exe
	rm -rf $(BUILDDIR)/* $(PKGDIR)/*

distclean: clean
	rm -f go.sum

gotest:
	go vet -tests=false ./...
	go test -race -count 1 -v ./...

# Pass through certain OKTA_* and ONELOGIN_* environment variables which could be considered sensitive.
# If the *_URL env var for a provider is not set, the rspec tests for that provider will be skipped.
# Other configuration is loaded from the testdata/aws_config file. Create matching profile names in your local
# .aws/credentials file, and the container will mount that and use it for testing.  Otherwise, set the OKTA_PASSWORD
# and/or ONELOGIN_PASSWORD env var to provide the idp credentials
rspec: $(EXE)
	mv $(EXE) $(BUILDDIR)

	@if [ -z $${CIRCLECI} ]; then \
		DOCKER_ARGS="--user root"; \
	fi; \
	docker run $${DOCKER_ARGS} --rm -it -w /app \
	  -e AWS_SHARED_CREDENTIALS_FILE=testdata/aws_credentials \
	  -e OKTA_SAML_URL -e OKTA_OIDC_URL -e OKTA_OIDC_CLIENT_ID -e OKTA_PASSWORD \
	  -e ONELOGIN_SAML_URL -e ONELOGIN_OIDC_URL -e ONELOGIN_OIDC_CLIENT_ID -e ONELOGIN_PASSWORD \
	  --mount type=bind,src=$${PWD},dst=/app \
	  --mount type=bind,src=$${HOME}/.aws/credentials,dst=/app/testdata/aws_credentials,ro \
	  --entrypoint scripts/run_rspec.sh cimg/ruby:2.7

test: gotest rspec

docs:
	@if [ -z $${CIRCLECI} ]; then \
  		DOCKER_ARGS="--user root"; \
	fi; \
	docker run --rm -v $${PWD}:/app -w /app -p 4000:4000 -it $${DOCKER_ARGS} --entrypoint scripts/run_jekyll.sh cimg/ruby:2.7
