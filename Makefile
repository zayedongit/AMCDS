# AMCDS developer entry points. Every target is safe to run repeatedly.
#
# This machine may have more than one Python (a system one, a Homebrew one, an
# Anaconda one). AMCDS needs 3.10+ with NetworkX 3.x; an older interpreter fails
# in confusing ways deep inside NetworkX. So the interpreter is a variable:
#
#     make test                                  # uses python3
#     make test PYTHON=/usr/local/bin/python3    # pick a specific one
#
# Run `make check` first if anything looks wrong.
PYTHON ?= python3

.PHONY: help check install test demo benchmark dashboard clean

help:
	@echo "make check      verify this Python can run AMCDS (run this first)"
	@echo "make install    install runtime + dev dependencies"
	@echo "make test       run the full test suite"
	@echo "make demo       run the walkthrough and write results/demo_report.json"
	@echo "make benchmark  run the seeded 45-scenario benchmark"
	@echo "make dashboard  launch the local dashboard at http://127.0.0.1:8000"
	@echo "make clean      remove caches and generated results"
	@echo ""
	@echo "Current interpreter: $(PYTHON)"
	@echo "Override with:       make <target> PYTHON=/path/to/python3"

check:
	@$(PYTHON) scripts/check_env.py

install:
	$(PYTHON) -m pip install -r requirements.txt -r requirements-dev.txt
	$(PYTHON) -m pip install -e .

test: check
	$(PYTHON) -m pytest tests/ -q

demo: check
	$(PYTHON) run_demo.py

benchmark: check
	$(PYTHON) scripts/run_benchmark.py

dashboard: check
	$(PYTHON) serve.py

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	rm -rf .pytest_cache *.egg-info
	rm -f results/demo_report.json results/benchmark.json
