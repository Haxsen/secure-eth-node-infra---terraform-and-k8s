# Local reproduction of CI. Only Docker (and kubectl, for `kustomize`) is
# required: every tool runs from the same digest-pinned image CI uses.
#
#   make lint   - fmt, validate, tflint, render, kubeconform, conftest, checkov, shellcheck, workflows
#   make test   - policy unit tests + gateway and validator functional tests
#   make ci     - both
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

export MSYS_NO_PATHCONV := 1
ROOT := $(shell pwd -W 2>/dev/null || pwd)
RUN := docker run --rm -v "$(ROOT):/repo" -w /repo

TERRAFORM_IMAGE  := hashicorp/terraform:1.17.2@sha256:6e9c1e647c31a960dc9b59e13272f9111d90010c10b717f77ffb324767660475
TFLINT_IMAGE     := ghcr.io/terraform-linters/tflint:v0.66.0@sha256:65b9944a9274c4989492c1d79998c2801664bf8a55fddb4bd3a9e6d73a006ddc
CONFTEST_IMAGE   := openpolicyagent/conftest:v0.71.1@sha256:0e77cdf7c1fcde035f3c579e4aaa6664ee2a8be5777eaa9af9f520cdd02280c0
KUBECONFORM_IMAGE:= ghcr.io/yannh/kubeconform:v0.8.0@sha256:faffaf43f95aa6425306e1ab8d6fcad72acb9049158f38e574c085ea1ec0f64e
CHECKOV_IMAGE    := bridgecrew/checkov:3.4.5@sha256:122602cf32cc72286155d39f1f234b7b594818f7b8d7fdf490701620e521368b
SHELLCHECK_IMAGE := koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d
ACTIONLINT_IMAGE := rhysd/actionlint:1.7.8@sha256:96d4a8c87dbbfb3bdd324f8fdc285fc3df5261e2decc619a4dd7e8ee52bbfd46
ZIZMOR_IMAGE     := ghcr.io/zizmorcore/zizmor:1.32.0@sha256:3014cc8f68f663935f69b3c3e0e41f5ce102b268d97db13db0f62208747f860d

ENVS := hoodi mainnet
CRD_SCHEMAS := https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json

.PHONY: help
help: ## Show targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-16s %s\n", $$1, $$2}'

# --- Terraform ----------------------------------------------------------------
.PHONY: fmt
fmt: ## terraform fmt (rewrite)
	$(RUN) $(TERRAFORM_IMAGE) -chdir=terraform fmt -recursive

.PHONY: tf-validate
tf-validate: ## terraform fmt -check + validate (both stacks)
	$(RUN) $(TERRAFORM_IMAGE) -chdir=terraform fmt -recursive -check -diff
	for stack in bootstrap platform; do \
	  $(RUN) -e TF_DATA_DIR=/tmp/tf --entrypoint sh $(TERRAFORM_IMAGE) -c \
	    "cd terraform/$$stack && terraform init -backend=false -input=false >/dev/null && terraform validate"; \
	done

.PHONY: tflint
tflint: ## tflint with the AWS ruleset
	mkdir -p .cache/tflint
	$(RUN) -v "$(ROOT)/.cache/tflint:/root/.tflint.d/plugins" -w /repo/terraform --entrypoint sh $(TFLINT_IMAGE) -c \
	  'tflint --config=/repo/.tflint.hcl --init >/dev/null && tflint --config=/repo/.tflint.hcl --recursive --format compact'

# --- Kubernetes -----------------------------------------------------------------
.PHONY: render
render: ## Render every overlay to rendered/<env>.yaml
	mkdir -p rendered
	for env in $(ENVS); do kubectl kustomize "k8s/overlays/$$env" > "rendered/$$env.yaml"; done

.PHONY: kubeconform
kubeconform: render ## Strict schema validation incl. CRDs
	$(RUN) $(KUBECONFORM_IMAGE) -strict -summary -schema-location default \
	  -schema-location '$(CRD_SCHEMAS)' $(addprefix rendered/,$(addsuffix .yaml,$(ENVS)))

.PHONY: policy
policy: render ## OPA/conftest policies against rendered manifests
	for env in $(ENVS); do \
	  $(RUN) $(CONFTEST_IMAGE) test --all-namespaces --policy policies/kubernetes "rendered/$$env.yaml"; \
	  $(RUN) $(CONFTEST_IMAGE) test --combine --namespace kubernetes.combined --policy policies/kubernetes "rendered/$$env.yaml"; \
	done

.PHONY: checkov
checkov: render ## Checkov on Terraform + rendered manifests
	$(RUN) $(CHECKOV_IMAGE) --config-file .checkov.yaml -d terraform -d rendered --framework terraform kubernetes

# --- Scripts & workflows ---------------------------------------------------------
.PHONY: shellcheck
shellcheck: ## shellcheck all scripts
	$(RUN) $(SHELLCHECK_IMAGE) -S warning scripts/*.sh k8s/base/validator/scripts/*.sh tests/*/run.sh

.PHONY: workflows
workflows: ## actionlint + zizmor on GitHub Actions
	$(RUN) $(ACTIONLINT_IMAGE) -no-color
	$(RUN) $(ZIZMOR_IMAGE) --offline .github/workflows

# --- Tests --------------------------------------------------------------------------
.PHONY: policy-test
policy-test: ## Rego unit tests
	$(RUN) $(CONFTEST_IMAGE) verify --policy policies

.PHONY: test-gateway
test-gateway: ## RPC gateway functional tests (Docker)
	bash tests/gateway/run.sh

.PHONY: test-validator
test-validator: ## Validator key-path tests with real keystores (Docker)
	bash tests/validator/run.sh

# --- Aggregates -----------------------------------------------------------------------
.PHONY: lint
lint: tf-validate tflint kubeconform policy checkov shellcheck workflows ## All static checks

.PHONY: test
test: policy-test test-gateway test-validator ## All tests

.PHONY: ci
ci: lint test ## Everything CI runs
