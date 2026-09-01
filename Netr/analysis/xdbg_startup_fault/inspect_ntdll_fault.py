import idapro
import sys
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_segment
import idautils
import idc


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: inspect_ntdll_fault.py <ntdll-copy> <rva>")
        return 2

    target = sys.argv[1]
    rva = int(sys.argv[2], 0)
    result = idapro.open_database(target, True)
    if result != 0:
        print(f"open_database failed: {result}")
        return result

    try:
        ida_auto.auto_wait()
        image_base = ida_nalt.get_imagebase()
        address = image_base + rva
        item = ida_bytes.get_item_head(address)
        function = ida_funcs.get_func(address)
        segment = ida_segment.getseg(address)

        print(f"image_base=0x{image_base:X}")
        print(f"rva=0x{rva:X} address=0x{address:X} item=0x{item:X}")
        if segment:
            print(
                f"segment={ida_segment.get_segm_name(segment)} "
                f"range=0x{segment.start_ea:X}-0x{segment.end_ea:X}"
            )
        if function:
            print(
                f"function={ida_funcs.get_func_name(function.start_ea)} "
                f"start=0x{function.start_ea:X} end=0x{function.end_ea:X} "
                f"fault_offset=0x{address - function.start_ea:X}"
            )
            start = max(function.start_ea, item - 0x60)
            end = min(function.end_ea, item + 0x70)
        else:
            print("function=<none>")
            start = item - 0x60
            end = item + 0x70

        print("\nDISASSEMBLY")
        for head in idautils.Heads(start, end):
            marker = ">>>" if head == item else "   "
            size = ida_bytes.get_item_size(head)
            raw = ida_bytes.get_bytes(head, size) or b""
            line = idc.generate_disasm_line(head, 0) or ""
            print(f"{marker} 0x{head:X}  {raw.hex(' ').upper():<28}  {line}")

        if function and ida_hexrays.init_hexrays_plugin():
            try:
                decompiled = ida_hexrays.decompile(function.start_ea)
            except ida_hexrays.DecompilationFailure:
                decompiled = None
            if decompiled:
                print("\nDECOMPILATION")
                for index, line in enumerate(str(decompiled).splitlines()):
                    if index >= 240:
                        print("...<truncated>")
                        break
                    print(line)
        return 0
    finally:
        idapro.close_database()


if __name__ == "__main__":
    raise SystemExit(main())
