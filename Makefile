wasm.py: jsc-wasm.json gen_wasm.py
	python3 gen_wasm.py > wasm.py
	python3 wasm.py
