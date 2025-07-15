from capstone import *
from collections import defaultdict
import json

# Инициализируем Capstone для x86_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

def bruteforce_opcodes():
    results = defaultdict(list)

    for opcode in range(0x0000, 0x10000):
        # Представляем число как 2 байта
        opcode_bytes = opcode.to_bytes(2, byteorder='little')

        try:
            for instr in md.disasm(opcode_bytes, 0x0):
                key = f"{instr.mnemonic} {instr.op_str}".strip()
                results[key].append(f"0x{opcode:04x}")
        except CsError:
            continue

    return results


if __name__ == "__main__":
    opcodes_mapping = bruteforce_opcodes()

    # Фильтруем только те, где больше одного представления
    filtered_mapping = {k: v for k, v in opcodes_mapping.items() if len(v) > 1}

    # json_output = json.dumps(filtered_mapping, indent=4)
    # print(json_output)

    # Сохраняем в JSON файл
    with open("opcodes_mapping.json", "w") as json_file:
        json.dump(filtered_mapping, json_file, indent=4)
