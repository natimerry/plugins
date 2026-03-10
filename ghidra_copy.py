import ida_bytes
import ida_kernwin
import ida_nalt
import ida_segment
import idaapi
import idc
from PyQt5.Qt import QAction, QApplication, QCursor, QMenu


def get_imagebase():
    return ida_nalt.get_imagebase()


def get_selection_or_item():
    start = idc.read_selection_start()
    end = idc.read_selection_end()
    if start == idc.BADADDR:
        start = idc.here()
        end = start + idc.get_item_size(start)
    return start, end


def to_clipboard(text):
    QApplication.clipboard().setText(text)
    print(f"[copied] {text}")


def copy_bytes(start, end):
    bs = [f"{ida_bytes.get_byte(a):02x}" for a in range(start, end)]
    return " ".join(bs)


def copy_bytes_no_space(start, end):
    bs = [f"{ida_bytes.get_byte(a):02x}" for a in range(start, end)]
    return "".join(bs)


def copy_rva(start, end):
    base = get_imagebase()
    rva_start = start - base
    rva_end = end - base
    if start == end - idc.get_item_size(start):
        return f"{rva_start:08x}"
    return f"{rva_start:08x} - {rva_end:08x}"


def copy_offset(start, end):
    """File offset (like Ghidra 'Copy Special > Offset')"""
    seg = ida_segment.getseg(start)
    if not seg:
        return f"No segment at {start:#x}"
    # IDA: file offset via ida_loader
    import ida_loader

    foff = ida_loader.get_fileregion_offset(start)
    return f"{foff:08x}"


def copy_address(start, end):
    return f"{start:016x}"


def copy_address_with_offset(start, end):
    base = get_imagebase()
    return f"imagebase+{start - base:#x}  ({start:#x})"


def copy_disasm(start, end):
    lines = []
    ea = start
    while ea < end:
        lines.append(idc.generate_disasm_line(ea, 0))
        ea = idc.next_head(ea, end)
    return "\n".join(lines)


def copy_bytes_with_disasm(start, end):
    lines = []
    ea = start
    while ea < end:
        size = idc.get_item_size(ea)
        bs = " ".join(f"{ida_bytes.get_byte(a):02x}" for a in range(ea, ea + size))
        dis = idc.generate_disasm_line(ea, 0)
        lines.append(f"{bs:<30} {dis}")
        ea = idc.next_head(ea, end)
    return "\n".join(lines)


def copy_python_bytearray(start, end):
    bs = [str(ida_bytes.get_byte(a)) for a in range(start, end)]
    return f"bytearray([{', '.join(bs)}])"


def copy_c_array(start, end):
    bs = [f"0x{ida_bytes.get_byte(a):02x}" for a in range(start, end)]
    return f"unsigned char data[] = {{{', '.join(bs)}}};"


def copy_yara_pattern(start, end):
    bs = [f"{ida_bytes.get_byte(a):02x}" for a in range(start, end)]
    return "{ " + " ".join(bs) + " }"


class GhidraCopyAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        start, end = get_selection_or_item()

        options = {
            "Copy Bytes (spaced)": lambda: copy_bytes(start, end),
            "Copy Bytes (no spaces)": lambda: copy_bytes_no_space(start, end),
            "Copy RVA": lambda: copy_rva(start, end),
            "Copy File Offset": lambda: copy_offset(start, end),
            "Copy Address (VA)": lambda: copy_address(start, end),
            "Copy Address (imagebase+offset)": lambda: copy_address_with_offset(
                start, end
            ),
            "Copy Disassembly": lambda: copy_disasm(start, end),
            "Copy Bytes + Disassembly": lambda: copy_bytes_with_disasm(start, end),
            "Copy as Python bytearray": lambda: copy_python_bytearray(start, end),
            "Copy as C Array": lambda: copy_c_array(start, end),
            "Copy as YARA Pattern": lambda: copy_yara_pattern(start, end),
        }

        menu = QMenu()
        actions = {}
        for label in options:
            act = QAction(label)
            menu.addAction(act)
            actions[act] = options[label]

        chosen = menu.exec_(QCursor.pos())
        if chosen and chosen in actions:
            result = actions[chosen]()
            to_clipboard(result)
            ida_kernwin.info(
                f"Copied:\n{result[:300]}{'...' if len(result) > 300 else ''}"
            )

        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


ACTION_NAME = "ghidra:copyspecial"
if ida_kernwin.unregister_action(ACTION_NAME):
    pass

ida_kernwin.register_action(
    ida_kernwin.action_desc_t(
        ACTION_NAME, "Ghidra Copy Special...", GhidraCopyAction(), "Ctrl+Alt+C"
    )
)

ida_kernwin.attach_action_to_menu(
    "Edit/Ghidra Copy Special", ACTION_NAME, ida_kernwin.SETMENU_APP
)

print("[*] Ghidra Copy Special registered — Ctrl+Alt+C")
