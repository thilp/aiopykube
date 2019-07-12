all: lint test

.poetry.fresh: poetry.lock
	poetry install
	touch $@

.PHONY: lint
lint: .poetry.fresh
	poetry run black --check . --exclude tests/
	poetry run flake8

.PHONY: format
format: .poetry.fresh
	poetry run black . --exclude tests/

.PHONY: test
test: test.unit

.PHONY: test.unit
test.unit: .poetry.fresh
	poetry run pytest --doctest-modules --cov=. tests/

coverage.html: test.unit
	poetry run coverage html -d $@
	touch $@
	if command -v open >/dev/null; then \
		open $@/index.html; \
	elif command -v xdg-open >/dev/null; then \
		xdg-open $@/index.html; \
	fi

