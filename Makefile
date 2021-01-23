.PHONY: docs

init:
	pip install -e .
	pip install -r requirements-dev.txt


lint:
	make black
	make flake8
	make prospector
black:
	black socialname
flake8:
	flake8 --max-line-length=120 socialname
prospector:
	prospector socialname


test:
	tox --parallel
coverage:
	pytest --cov-config .coveragerc --verbose --cov-report term --cov-report html --cov=socialname tests

sites:
	python scripts/site_list.py
publish:
	pip install twine
	python setup.py sdist bdist_wheel
	twine upload dist/*
	rm -fr build dist .egg socialname.egg-info
