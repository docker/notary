# Set an output prefix, which is the local directory if not specified
PREFIX?=$(shell pwd)

# Populate version variables
# Add to compile time flags
NOTARY_PKG := github.com/docker/notary
NOTARY_VERSION := $(shell cat NOTARY_VERSION)
GITCOMMIT := $(shell git rev-parse --short HEAD)
GITUNTRACKEDCHANGES := $(shell git status --porcelain --untracked-files=no)
ifneq ($(GITUNTRACKEDCHANGES),)
GITCOMMIT := $(GITCOMMIT)-dirty
endif
CTIMEVAR=-X $(NOTARY_PKG)/version.GitCommit=$(GITCOMMIT) -X $(NOTARY_PKG)/version.NotaryVersion=$(NOTARY_VERSION)
GO_LDFLAGS=-ldflags "-w $(CTIMEVAR)"
GO_LDFLAGS_STATIC=-ldflags "-w $(CTIMEVAR) -extldflags -static"
GOOSES = darwin linux
NOTARY_BUILDTAGS ?= pkcs11
NOTARYDIR := /go/src/github.com/docker/notary

GO_VERSION := $(shell go version | grep "1\.[7-9]\(\.[0-9]+\)*\|devel")
# check to make sure we have the right version. development versions of Go are
# not officially supported, but allowed for building

ifeq ($(strip $(GO_VERSION))$(SKIPENVCHECK),)
$(error Bad Go version - please install Go >= 1.7)
endif

# check to be sure pkcs11 lib is always imported with a build tag
GO_LIST_PKCS11 := $(shell go list -tags "${NOTARY_BUILDTAGS}" -e -f '{{join .Deps "\n"}}' ./... | grep -v /vendor/ | xargs go list -e -f '{{if not .Standard}}{{.ImportPath}}{{end}}' | grep -q pkcs11)
ifeq ($(GO_LIST_PKCS11),)
$(info pkcs11 import was not found anywhere without a build tag, yay)
else
$(error You are importing pkcs11 somewhere and not using a build tag)
endif

_empty :=
_space := $(empty) $(empty)

# go cover test variables
COVERDIR=.cover
COVERPROFILE?=$(COVERDIR)/cover.out
COVERMODE=count
PKGS ?= $(shell go list -tags "${NOTARY_BUILDTAGS}" ./... | grep -v /vendor/ | tr '\n' ' ')

.PHONY: clean all lint build test binaries cross cover docker-images notary-dockerfile
.DELETE_ON_ERROR: cover
.DEFAULT: default

all: AUTHORS clean lint build test binaries

AUTHORS: .git/HEAD
	git log --format='%aN <%aE>' | sort -fu > $@

# This only needs to be generated by hand when cutting full releases.
version/version.go:
	./version/version.sh > $@

${PREFIX}/bin/notary-server: NOTARY_VERSION $(shell find . -type f -name '*.go')
	@echo "+ $@"
	@go build -tags ${NOTARY_BUILDTAGS} -o $@ ${GO_LDFLAGS} ./cmd/notary-server

${PREFIX}/bin/notary: NOTARY_VERSION $(shell find . -type f -name '*.go')
	@echo "+ $@"
	@go build -tags ${NOTARY_BUILDTAGS} -o $@ ${GO_LDFLAGS} ./cmd/notary

${PREFIX}/bin/notary-signer: NOTARY_VERSION $(shell find . -type f -name '*.go')
	@echo "+ $@"
	@go build -tags ${NOTARY_BUILDTAGS} -o $@ ${GO_LDFLAGS} ./cmd/notary-signer

ifeq ($(shell uname -s),Darwin)
${PREFIX}/bin/static/notary-server:
	@echo "notary-server: static builds not supported on OS X"

${PREFIX}/bin/static/notary-signer:
	@echo "notary-signer: static builds not supported on OS X"

${PREFIX}/bin/static/notary:
	@echo "notary: static builds not supported on OS X"
else
${PREFIX}/bin/static/notary-server: NOTARY_VERSION $(shell find . -type f -name '*.go')
	@echo "+ $@"
	@go build -tags ${NOTARY_BUILDTAGS} -o $@ ${GO_LDFLAGS_STATIC} ./cmd/notary-server

${PREFIX}/bin/static/notary-signer: NOTARY_VERSION $(shell find . -type f -name '*.go')
	@echo "+ $@"
	@go build -tags ${NOTARY_BUILDTAGS} -o $@ ${GO_LDFLAGS_STATIC} ./cmd/notary-signer

${PREFIX}/bin/static/notary:
	@echo "+ $@"
	@go build -tags ${NOTARY_BUILDTAGS} -o $@ ${GO_LDFLAGS_STATIC} ./cmd/notary
endif


# run all lint functionality - excludes Godep directory, vendoring, binaries, python tests, and git files
lint:
	@echo "+ $@: golint, go vet, go fmt, misspell, ineffassign"
	# golint
	@test -z "$(shell find . -type f -name "*.go" -not -path "./vendor/*" -not -name "*.pb.*" -exec golint {} \; | tee /dev/stderr)"
	# gofmt
	@test -z "$$(gofmt -s -l .| grep -v .pb. | grep -v vendor/ | tee /dev/stderr)"
	# govet
ifeq ($(shell uname -s), Darwin)
	@test -z "$(shell find . -iname *test*.go | grep -v _test.go | grep -v vendor | xargs echo "This file should end with '_test':"  | tee /dev/stderr)"
else
	@test -z "$(shell find . -iname *test*.go | grep -v _test.go | grep -v vendor | xargs -r echo "This file should end with '_test':"  | tee /dev/stderr)"
endif
	@test -z "$$(go tool vet -printf=false . 2>&1 | grep -v vendor/ | tee /dev/stderr)"
	# misspell - requires that the following be run first:
	#    go get -u github.com/client9/misspell/cmd/misspell
	@test -z "$$(find . -type f | grep -v vendor/ | grep -v bin/ | grep -v misc/ | grep -v .git/ | grep -v \.pdf | xargs misspell | tee /dev/stderr)"
	# ineffassign - requires that the following be run first:
	#    go get -u github.com/gordonklaus/ineffassign
	@test -z "$(shell find . -type f -name "*.go" -not -path "./vendor/*" -not -name "*.pb.*" -exec ineffassign {} \; | tee /dev/stderr)"

build:
	@echo "+ $@"
	@go build -tags "${NOTARY_BUILDTAGS}" -v ${GO_LDFLAGS} $(PKGS)

# When running `go test ./...`, it runs all the suites in parallel, which causes
# problems when running with a yubikey
test: TESTOPTS =
test:
	@echo Note: when testing with a yubikey plugged in, make sure to include 'TESTOPTS="-p 1"'
	@echo "+ $@ $(TESTOPTS)"
	@echo
	go test -tags "${NOTARY_BUILDTAGS}" $(TESTOPTS) $(PKGS)

integration: TESTDB = mysql
integration: clean
	buildscripts/integrationtest.sh $(TESTDB)

testdb: TESTDB = mysql
testdb:
	buildscripts/dbtests.sh $(TESTDB)

protos:
	@protoc --go_out=plugins=grpc:. proto/*.proto

# This allows coverage for a package to come from tests in different package.
# Requires that the following:
# go get github.com/wadey/gocovmerge; go install github.com/wadey/gocovmerge
#
# be run first
gen-cover:
gen-cover:
	@mkdir -p "$(COVERDIR)"
	python -u buildscripts/covertest.py --coverdir "$(COVERDIR)" --tags "$(NOTARY_BUILDTAGS)" --pkgs="$(PKGS)" --testopts="${TESTOPTS}"

# Generates the cover binaries and runs them all in serial, so this can be used
# run all tests with a yubikey without any problems
cover: gen-cover covmerge
	@go tool cover -html="$(COVERPROFILE)"

# Generates the cover binaries and runs them all in serial, so this can be used
# run all tests with a yubikey without any problems
ci: override TESTOPTS = -race
# Codecov knows how to merge multiple coverage files, so covmerge is not needed
ci: gen-cover

yubikey-tests: override PKGS = github.com/docker/notary/cmd/notary github.com/docker/notary/trustmanager/yubikey
yubikey-tests: ci

covmerge:
	@gocovmerge $(shell ls -1 $(COVERDIR)/* | tr "\n" " ") > $(COVERPROFILE)
	@go tool cover -func="$(COVERPROFILE)"

clean-protos:
	@rm proto/*.pb.go

client: ${PREFIX}/bin/notary
	@echo "+ $@"

binaries: ${PREFIX}/bin/notary-server ${PREFIX}/bin/notary ${PREFIX}/bin/notary-signer
	@echo "+ $@"

static: ${PREFIX}/bin/static/notary-server ${PREFIX}/bin/static/notary-signer ${PREFIX}/bin/static/notary
	@echo "+ $@"

notary-dockerfile:
	@docker build --rm --force-rm -t notary .

server-dockerfile:
	@docker build --rm --force-rm -f server.Dockerfile -t notary-server .

signer-dockerfile:
	@docker build --rm --force-rm -f signer.Dockerfile -t notary-signer .

docker-images: notary-dockerfile server-dockerfile signer-dockerfile

shell: notary-dockerfile
	docker run --rm -it -v $(CURDIR)/cross:$(NOTARYDIR)/cross -v $(CURDIR)/bin:$(NOTARYDIR)/bin notary bash

cross: notary-dockerfile
	@rm -rf $(CURDIR)/cross
	docker run --rm -v $(CURDIR)/cross:$(NOTARYDIR)/cross -e NOTARY_BUILDTAGS=$(NOTARY_BUILDTAGS) notary buildscripts/cross.sh $(GOOSES)


clean:
	@echo "+ $@"
	@rm -rf "$(COVERDIR)" cross
	@rm -rf "${PREFIX}/bin/notary-server" "${PREFIX}/bin/notary" "${PREFIX}/bin/notary-signer"
