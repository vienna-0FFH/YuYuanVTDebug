import sys

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: inspect_ntdll_fault_capstone.py <ntdll> <rva>")
        return 2

    path = sys.argv[1]
    fault_rva = int(sys.argv[2], 0)
    pe = pefile.PE(path, fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    function_start = None
    function_end = None
    for entry in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []):
        begin = entry.struct.BeginAddress
        end = entry.struct.EndAddress
        if begin <= fault_rva < end:
            function_start = begin
            function_end = end
            break

    if function_start is None:
        function_start = max(0, fault_rva - 0x100)
        function_end = fault_rva + 0x100

    nearest_export = None
    nearest_delta = None
    export_directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export_directory:
        for symbol in export_directory.symbols:
            if symbol.address <= fault_rva:
                delta = fault_rva - symbol.address
                if nearest_delta is None or delta < nearest_delta:
                    nearest_export = symbol
                    nearest_delta = delta

    code = pe.get_data(function_start, function_end - function_start)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code, image_base + function_start))
    fault_va = image_base + fault_rva
    fault_index = next(
        (index for index, instruction in enumerate(instructions)
         if instruction.address == fault_va),
        None,
    )

    print(f"image_base=0x{image_base:X}")
    print(f"fault_rva=0x{fault_rva:X} fault_va=0x{fault_va:X}")
    print(
        f"runtime_function=0x{function_start:X}-0x{function_end:X} "
        f"size=0x{function_end - function_start:X}"
    )
    if nearest_export:
        name = nearest_export.name.decode("ascii", errors="replace") \
            if nearest_export.name else f"ordinal_{nearest_export.ordinal}"
        print(
            f"nearest_export={name} rva=0x{nearest_export.address:X} "
            f"delta=0x{nearest_delta:X}"
        )

    if fault_index is None:
        print("fault instruction boundary not found")
        return 1

    start_index = max(0, fault_index - 28)
    end_index = min(len(instructions), fault_index + 29)
    print("\nDISASSEMBLY")
    for index in range(start_index, end_index):
        instruction = instructions[index]
        marker = ">>>" if index == fault_index else "   "
        raw = " ".join(f"{byte:02X}" for byte in instruction.bytes)
        print(
            f"{marker} 0x{instruction.address:X} "
            f"{raw:<30} {instruction.mnemonic:<8} {instruction.op_str}"
        )

    fault = instructions[fault_index]
    print(
        f"\nFAULT_INSTRUCTION bytes={fault.bytes.hex().upper()} "
        f"mnemonic={fault.mnemonic} operands={fault.op_str}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
