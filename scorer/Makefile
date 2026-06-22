.PHONY: build vet test run mock clean

build:  ; go build -o scorer .
vet:    ; go vet ./...
test:   ; go test ./...
mock:   ; ./scorer --mock < sample-events.jsonl
run:    ; ./scorer --model $${OLLAMA_MODEL:-llama3.2:1b} < sample-events.jsonl
clean:  ; rm -f scorer
