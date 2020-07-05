# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=cswizard
PREFIX?="/"
BIN_PREFIX = $(PREFIX)"/usr/local/bin/"

all: clean build

build: clean
	@$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME) -v

static: clean
	@$(GOBUILD) -o $(BINARY_NAME) -v -a -tags netgo -ldflags '-w -extldflags "-static"'


clean:
	@rm -f $(BINARY_NAME)
