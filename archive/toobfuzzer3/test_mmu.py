import json
from linker_gen.chip_generator2 import generate_chip_capabilities, generate_flash_hal

with open('blueprints/esp32/run_85/blueprint.json') as f:
    bp = json.load(f)
with open('blueprints/quirks/esp32.json') as f:
    q = json.load(f)

def deep_update(d, u):
    for k, v in u.items():
        if isinstance(v, dict) and k in d and isinstance(d[k], dict):
            deep_update(d[k], v)
        else:
            d[k] = v

deep_update(bp["esp32"], q)

with open('test_out.c', 'w') as f:
    f.write(generate_flash_hal("esp32", bp["esp32"].get("flash_controller", {})))
