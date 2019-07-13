SRCDIR := aiopykube
TESTDIR := tests
SOURCES := $(shell find $(SRCDIR) -name '*.py')
UNITTESTS := $(shell find $(TESTDIR) -name '*.py')

all: lint test

# Ensures that all dependencies are installed.
.make/poetry.install: poetry.lock
	poetry install
	@mkdir -p .make
	@touch $@ .make/poetry.install.self

.PHONY: repl
repl: .make/poetry.install.self
	poetry run ipython

# Like .make/poetry.install, but also installs aiopykube.
# This rule's body is basically the same as .make/poetry.install, but the
# target file and dependencies are different.
# We can't merge both, because we don't want to run `poetry install` before
# every `make test` just because $(SOURCES) has changed.
.make/poetry.install.self: poetry.lock $(SOURCES)
	poetry install
	@mkdir -p .make
	@touch $@ .make/poetry.install

.PHONY: lint
lint: .make/black.check .make/flake8

.PHONY: format
format: .make/black.format

.make/black.check: .make/poetry.install $(SOURCES)
	poetry run black --check --diff $(SRCDIR)
	@touch $@

.make/black.format: .make/poetry.install $(SOURCES)
	poetry run black $(SRCDIR)
	@touch $@

.make/flake8: .make/poetry.install $(SOURCES) .flake8
	poetry run flake8
	@touch $@

.PHONY: test
test: test.unit

.PHONY: test.unit
test.unit: .coverage

.coverage: .make/poetry.install $(SOURCES) $(UNITTESTS)
	poetry run pytest --doctest-modules --cov=$(SRCDIR) $(TESTDIR)

coverage.html: .coverage
	poetry run coverage html -d $@
	@touch $@
	if command -v open >/dev/null; then \
		open $@/index.html; \
	elif command -v xdg-open >/dev/null; then \
		xdg-open $@/index.html; \
	fi

.PHONY: clean
clean:
	find $(SRCDIR) $(TESTDIR) \( -name __pycache__ -o -name .pytest_cache \) -exec rm -r '{}' +
	rm -rf *.egg-info/ dist/
	rm -rf .coverage coverage.html/
	rm -rf .make/
