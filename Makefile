# uefi-supply-chain — entry points.
# `make help` lists targets. The self-contained targets (test, coverage) need
# only opa + jq + python3(+PyYAML); the full demo also needs cosign + grype.

SHELL := /bin/bash
ROOT  := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
FIX   := $(ROOT)oss-lane/fixtures
VSA   := /tmp/fw-vsa.json

.DEFAULT_GOAL := help

.PHONY: help
help: ## List targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: deps
deps: ## Install Python deps (hash-pinned PyYAML + pefile) + fetch pinned opa (SHA-verified)
	pip install --require-hashes -r requirements.txt
	ONLY=opa bash scripts/fetch-tools.sh

.PHONY: bin
bin: ## Fetch + SHA-verify ALL pinned CLI tools (opa, cosign, grype) into bin/ — needed for `make demo`
	bash scripts/fetch-tools.sh

.PHONY: test
test: ## Gate honesty tests (opa+jq) + assembler + byte-integrity unit tests + cosign-native policy. coSWID/PEI tests need python-uswid+pefile; set COSWID_PY=<venv>/bin/python to run them (else they SKIP loudly). Use `make test-full` to REQUIRE them.
	bash tests/run.sh
	python3 tests/test_assemble.py
	$(or $(COSWID_PY),python3) tests/test_byte_integrity.py
	$(or $(COSWID_PY),python3) tests/test_profile_conformance.py
	$(or $(COSWID_PY),python3) tests/test_deploy_reconcile.py
	$(or $(COSWID_PY),python3) tests/test_efilist_interop.py
	python3 tests/test_attack_demo.py
	python3 tests/test_reconcile.py
	python3 tests/test_chipsec.py
	python3 tests/test_interop.py
	$(or $(COSWID_PY),python3) tests/test_coswid.py $(COSWID_TEST_FLAGS)
	python3 tests/test_initiatives_sync.py
	OPA=$(or $(OPA),$(ROOT)bin/opa) python3 tests/test_evidence_grade.py
	python3 tests/test_cli_verdict.py
	OPA=$(or $(OPA),$(ROOT)bin/opa) bash tests/pipeline-negative.sh
	bash tests/cosign-policy.sh

.PHONY: test-full
test-full: ## Like `test` but REQUIRES python-uswid + pefile so the coSWID round-trip + PEI/XIP BUG-1 regression actually run (fail, not skip). Usage: COSWID_PY=<venv>/bin/python make test-full
	@test -n "$(COSWID_PY)" || { echo "set COSWID_PY=<venv>/bin/python (a python with python-uswid + pefile installed)"; exit 2; }
	$(MAKE) test COSWID_PY="$(COSWID_PY)" COSWID_TEST_FLAGS=--require-deps

.PHONY: coverage
coverage: ## Per-framework, per-control coverage from a fresh signed VSA (opa+python+PyYAML)
	@VSA_OUT=$(VSA) bash oss-lane/gate.sh $(FIX)/clean.json >/dev/null
	@python3 oss-lane/verify-initiative.py --vsa $(VSA)

.PHONY: gate
gate: ## Run the gate on one fixture: make gate FIXTURE=oss-lane/fixtures/clean.json
	bash oss-lane/gate.sh $(or $(FIXTURE),$(FIX)/clean.json)

.PHONY: verify
verify: ## Consumer CLI on your firmware: make verify FW=<image.fd> VSA=<vsa.json>
	@test -n "$(FW)" || { echo "usage: make verify FW=<image.fd> [VSA=<vsa.json>]"; exit 2; }
	cli/fw-supplychain-verify --firmware "$(FW)" $(if $(VSA),--vsa "$(VSA)",)

.PHONY: demo
demo: ## Full OSS lane end to end (needs cosign + grype + opa). Add FW_IMAGE=<deployed .fd> for a REAL leg-3 flash-time measurement (SP 800-193 §4.3.1 -> 46/46); without it §4.3.1 stays advisory (45/46).
	bash oss-lane/run.sh

.PHONY: reconcile
reconcile: ## Carve a real image + reconcile: make reconcile EDK2=<tree> IMG=<image.fd>
	@test -n "$(EDK2)" -a -n "$(IMG)" || { echo "usage: make reconcile EDK2=<edk2 tree> IMG=<image.fd>"; exit 2; }
	EDK2=$(EDK2) bash producers/reconcile/carve.sh $(IMG)

.PHONY: deploy-reconcile
deploy-reconcile: ## Track A deploy-time reconcile: CHIPSEC `uefi decode` a deployed image + reconcile per-module bytes vs the signed SBOM. Usage: make deploy-reconcile IMG=<image.fd> [SBOM=<sbom.cdx.json>]  (or DECODE_DIR=<chipsec_util uefi decode tree>). Needs chipsec_util on PATH for the IMG path.
	@test -n "$(IMG)" -o -n "$(DECODE_DIR)" || { echo "usage: make deploy-reconcile IMG=<image.fd> [SBOM=<sbom.cdx.json>]  (or DECODE_DIR=<chipsec_util uefi decode tree>)"; exit 2; }
	python3 producers/chipsec/deploy-reconcile.py \
	  --sbom $(or $(SBOM),inputs/sbom.cdx.json) \
	  $(if $(DECODE_DIR),--decode-dir "$(DECODE_DIR)",--image "$(IMG)") \
	  -o inputs/deploy-reconcile.json

.PHONY: attack-demo
attack-demo: ## "Same-GUID trojan caught": byte-tamper a real module under its GUID; real producer -> MODIFIED -> gate DENY. Add FW_IMAGE=<OVMF.fd> EDK2=<tree> for the full real-image run.
	OPA=$(or $(OPA),$(ROOT)bin/opa) bash scripts/attack-demo.sh

.PHONY: multi-firmware-demo
multi-firmware-demo: ## Run the SAME gate over three firmware profiles (X clean / Y authentic-but-vulnerable / Z tampered) and print a ✅/⛔ comparison table + per-⛔ remediation (needs opa + python3)
	OPA=$(or $(OPA),$(ROOT)bin/opa) bash scripts/multi-firmware-demo.sh

.PHONY: provider-comparison
provider-comparison: ## Rate real firmware providers (Dell/Lenovo coSWID, our OVMF, prebuilt/coreboot/Intel) on SBOM-transparency dimensions from LIVE probes; a missing artifact -> UNKNOWN, never a fabricated pass
	python3 scripts/provider-comparison.py

.PHONY: coswid-demo
coswid-demo: ## coSWID emit + FULL-LOOP proof: emit coSWID (source+shipped-byte hash) -> PE .sbom embed/extract -> ingest -> reconcile -> byte-integrity -> gate ALLOW/DENY. Needs python-uswid: COSWID_PY=<venv>/bin/python USWID=<venv>/bin/uswid make coswid-demo
	OPA=$(or $(OPA),$(ROOT)bin/opa) bash scripts/coswid-demo.sh

.PHONY: byte-integrity
.PHONY: verify-profile
verify-profile: ## Check the normalized-hash profile vectors still reproduce: make verify-profile EDK2=<tree> IMG=<image.fd>
	@test -n "$(EDK2)" -a -n "$(IMG)" || { echo "usage: make verify-profile EDK2=<edk2 tree> IMG=<image.fd>"; exit 2; }
	python3 producers/reconcile/profile-vectors.py --check docs/normalized-module-hash-vectors.json \
	        --sbom inputs/sbom.cdx.json --image "$(IMG)" --edk2 "$(EDK2)"

byte-integrity: ## Regenerate byte-integrity: make byte-integrity EDK2=<tree> IMG=<image.fd> (needs pefile+FMMT, ~6min)
	@test -n "$(EDK2)" -a -n "$(IMG)" || { echo "usage: make byte-integrity EDK2=<edk2 tree> IMG=<image.fd>"; exit 2; }
	python3 producers/reconcile/byte-integrity.py --sbom inputs/sbom.cdx.json --image "$(IMG)" --edk2 "$(EDK2)" -o inputs/byte-integrity.json

.PHONY: clean
clean: ## Remove generated local artifacts (keys, gate inputs, VSAs)
	rm -f inputs/gate-input.json inputs/sbom.att.bundle inputs/build-tools.cdx.json $(VSA) inputs/grype.json
	rm -rf oss-lane/.keys

.PHONY: refresh-kev
refresh-kev: ## Refresh data.cisa_kev from the live CISA KEV catalog (needs network)
	bash scripts/refresh-kev.sh
