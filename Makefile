build:
	go mod tidy

gen-proto:
	buf generate .

test: build gen-proto
	go test github.com/buffioconnect/test -v -count 1 -timeout 30s

clean:
	rm -rf ./gen/

.PHONY: build gen-proto test clean
