# build steps including dependencies.
# You do not have to use these but they are the canonical steps.
# You can pass some flags in:
#   GOBUILDFLAGS controls the go build/install step
#   GOTESTFLAGS controls the go test step

all: test install

.PHONY: install test govendor

# Build
VERSION = '$(shell git describe --tags --always --dirty)'
GOVERSION = '$(shell go version)'
BUILDTIME = '$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")'
install: govendor
	touch cmd/sneaker/version.go
	${GOPATH}/bin/govendor sync
	${GOPATH}/bin/govendor install $(GOBUILDFLAGS) -ldflags "-X \"main.version=$(VERSION)\" -X \"main.goVersion=$(GOVERSION)\" -X \"main.buildTime=$(BUILDTIME)\"" +local

# run tests
test: govendor
	${GOPATH}/bin/govendor test $(GOTESTFLAGS) +local

# Bootstrap govendor
govendor: ${GOPATH}/bin/govendor
${GOPATH}/bin/govendor:
	go get -u github.com/kardianos/govendor
	go install github.com/kardianos/govendor
