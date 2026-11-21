SHELL := /bin/bash
.PHONY: build test check lint tools kind-test demo clean
build:
	go build -trimpath -o bin/kube-impact ./cmd/kube-impact
test:
	go test -race -count=1 ./...
lint:
	test -z "$$(gofmt -l cmd internal test)"
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
	go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 -shellcheck=
check: build test lint
kind-test: build
	scripts/kind-test.sh examples/head artifacts/kind
demo: build
	bin/kube-impact report --base examples/base --head examples/scenarios/a-resources --output artifacts/report.md
tools:
	scripts/install-tools.sh
clean:
	rm -rf bin .build artifacts coverage.out
