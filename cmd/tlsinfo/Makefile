all:
	go run main.go github.com

check: 
	gofmt -w -s .
	go vet .
	golangci-lint run
	staticcheck

examples:
	go run main.go github.com
	go run main.go paepcke.de
