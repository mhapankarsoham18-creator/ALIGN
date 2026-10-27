.PHONY: install lint test eval heldout run run-demo demo docker smoke

install:
	pip install -r requirements-dev.txt

lint:
	ruff check . && ruff format --check . && mypy gateway detector deploy

test:
	pytest tests/unit tests/integration tests/load --cov=gateway --cov=detector --cov-fail-under=80

eval:
	python -m eval.run --scenarios eval/scenarios --out eval/report.json
	python -m eval.gate --report eval/report.json --min-recall 0.90 --max-fpr 0.05 --max-ttd-events 3

heldout:
	python -m eval.heldout

run:
	python -m gateway --reload --port 8000

run-demo:
	python -m gateway --demo --port 8000

demo:
	python -m simulator.run --scenario procurement_injection

smoke:
	python -m deploy.ops smoke staging

docker:
	docker build -t aidds:local .
