TANGENT ?= tangent

# The project, in the environment or on the command line
# (make run SUPABASE_PROJECT_REF=... SUPABASE_ACCESS_TOKEN=...):
#   SUPABASE_PROJECT_REF    the project's reference: Project Settings → General
#   SUPABASE_ACCESS_TOKEN   a Management API access token that can read its logs (analytics:read)
#   SUPABASE_SINCE          how far back the first run reads: 1h by default, a day at most is wise
# The judge: any OpenAI-compatible endpoint, a local model on :8080 by default
# (packs/judge/ingest.yaml has the defaults). A hosted one:
#   JUDGE_URL=https://api.openai.com/v1 JUDGE_MODEL=gpt-5.1 JUDGE_API_KEY=$OPENAI_API_KEY make run

# The plugins, one of two ways, as in examples/cloud-infra: `fetch`, prebuilt
# from the release of this tangent's version, or `compile`, built here from
# source for a tangent built from a checkout:  make run PLUGINS=compile
PLUGINS ?= fetch

setup:
	../cloud-infra/setup.sh

fetch: setup
	$(TANGENT) plugin fetch --config tangent.yaml

compile:
	../cloud-infra/setup.sh toolchain
	$(TANGENT) plugin compile --config tangent.yaml

# The pack's fixtures; no project and no model needed.
test: $(PLUGINS)
	$(TANGENT) plugin test --config tangent.yaml

run: $(if $(filter compile,$(PLUGINS)),compile,setup)
	$(TANGENT) run --config tangent.yaml

.PHONY: setup fetch compile test run
