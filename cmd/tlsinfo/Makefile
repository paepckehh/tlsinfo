all:
	go run main.go github.com

check: 
	gofmt -w -s .
	CGO_ENABLED=0 go vet .
	CGO_ENABLED=0 go fix -diff .
	CGO_ENABLED=0 go fix .
	CGO_ENABLED=0 golangci-lint run
	# CGO_ENABLED=0 staticcheck

examples:
	go run main.go github.com
	go run main.go paepcke.de
