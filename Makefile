.PHONY: default, lint

default:
	python -m Exjobb 
spell:
	codespell . --ignore-words-list=hist --skip=./.* --quiet-level=2 || true
lint:
	pylint Exjobb 
pep8:
	autopep8 Exjobb  --in-place --recursive --aggressive --aggressive
clean:
	rm -rf build/ dist/ Exjobb_manager.egg-info/
test:
	codespell . --ignore-words-list=hist --quiet-level=2
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
	pytest
reinstall:
	pip uninstall Exjobb 
	pyenv rehash
	pip install .
	pyenv rehash
