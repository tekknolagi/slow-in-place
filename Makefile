wasm_opcodes.py: jsc-wasm.json gen_opcodes.py
	python3 gen_opcodes.py > wasm_opcodes.py
	python3 wasm_opcodes.py
