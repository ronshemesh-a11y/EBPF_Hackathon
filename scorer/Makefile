.PHONY: build vet test run mock clean

build:  ; go build -o scorer .
vet:    ; go vet ./...
test:   ; go test ./...
mock:   ; ./scorer --mock < sample-events.jsonl
run:    ; ./scorer --model $${OLLAMA_MODEL:-phi3} < sample-events.jsonl
clean:  ; rm -f scorer
