import json

with open("jsc-wasm.json", "r") as f:
    wasm = json.load(f)


for name, entry in wasm["section"].items():
    upcase_name = name.upper()
    print(f"SEC_{upcase_name} = {entry['value']}")

seen = set()
for name, entry in wasm["opcode"].items():
    upcase_name = name.upper().replace(".", "_").replace("/", "_")
    value = entry["value"]
    if value in (
        0xFB,
        0xFC,
        0xFD,
        0xFE,
    ):
        # We'll ignore vector instructions and other prefix instructions for
        # now
        continue
    if value in seen:
        raise ValueError(f"Duplicate opcode {value}")
    seen.add(value)
    hex_value = hex(value).upper()
    print(f"{upcase_name} = {hex_value}")
