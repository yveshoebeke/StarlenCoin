SRCDIR = /Users/yves/Projects/StarlenCoin/

build:
	go build -o $(SRCDIR)main main.go

run:
	export BC_CONFIG_PATH=/Users/yves/Projects/StarlenCoin/data/config/starlencoin.toml	

	./$(SCRDIR)main

all: build run
