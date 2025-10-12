all:
	go run main.go github.com

check: 
	gofmt -w -s .
	CGO_ENABLED=0 go vet .
	CGO_ENABLED=0 staticcheck
	CGO_ENABLED=0 golangci-lint run

examples:
	go run main.go github.com
	go run main.go paepcke.de
