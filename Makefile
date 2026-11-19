# Convenience targets. Every target only runs commands shown here.
.PHONY: test lint format demo evidence

test:      ## run the whole test suite
	python3 -m pytest -v

lint:      ## ShellCheck and shfmt (formatting check only)
	shellcheck -x bin/dfir-triage lib/*.sh
	shfmt -d -i 4 -ci bin/dfir-triage lib/*.sh

format:    ## rewrite shell files with the project formatting
	shfmt -w -i 4 -ci bin/dfir-triage lib/*.sh

demo:      ## triage the bundled synthetic evidence into ./dfir-cases
	./bin/dfir-triage --evidence demo-case/evidence/ws01_triage_synthetic.bin --case-id CASE-DEMO-001

evidence:  ## rebuild the synthetic evidence (output is identical every time)
	python3 demo-case/tools/build_synthetic_evidence.py --out-dir demo-case/evidence
