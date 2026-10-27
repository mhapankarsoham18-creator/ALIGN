.PHONY: install lint test eval run demo docker

install:
	pip install -r requirements-dev.txt

lint:
	ruff check . && ruff format --check . && mypy gateway detector

test:
	pytest tests/unit tests/integration

eval:
	python -m eval.run --scenarios eval/scenarios --out eval/report.json
	python -m eval.gate --report eval/report.json --min-recall 0.90 --max-fpr 0.05 --max-ttd-events 3

run:
	uvicorn gateway.main:app --reload --port 8000

demo:
	python -m simulator.run --scenario procurement_injection

docker:
	docker build -t aidds:local .
