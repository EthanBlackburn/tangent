build:
	./setup.sh
	tangent plugin compile --config tangent.yaml

test: build
	tangent plugin test --config tangent.yaml

run: build
	tangent watch --config tangent.yaml

.PHONY: build test run
