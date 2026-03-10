import idaapi
import ida_segment

class MarvelReclass(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MarvelReclass: reclassifies segments when analyzing Marvel executables to make it so that it analyzes all the way automatically"
    help    = ""
    wanted_name = "MarvelReclass"
    wanted_hotkey = "" 

    def init(self):
        fname = idaapi.get_root_filename()
        if not fname:
            return idaapi.PLUGIN_SKIP
        
        # Check if filename matches any of the Marvel executable patterns
        fname_lower = fname.lower()
        marvel_executables = [
            "marvel.exe",
            "marvel-win64-test.exe", 
            "marvel-win64-shipping.exe"
        ]
        
        if fname_lower not in marvel_executables:
            return idaapi.PLUGIN_SKIP

        idaapi.msg(f"[MarvelReclass] Detected {fname}!\n")
        idaapi.msg("[MarvelReclass] Beginning segment reclassification...\n")

        seg = ida_segment.get_first_seg()
        while seg:
            sname = ida_segment.get_segm_name(seg)
            sclass = ida_segment.get_segm_class(seg)

            idaapi.msg(f"[MarvelReclass] Found segment '{sname}', class = '{sclass}'\n")

            if sname.lower() != ".text" and sclass.upper() == "CODE":
                idaapi.msg(f"[MarvelReclass] → Changing segment '{sname}' class from CODE to DATA\n")
                ida_segment.set_segm_class(seg, "DATA")

                new_class = ida_segment.get_segm_class(seg)
                idaapi.msg(f"[MarvelReclass] → Now '{sname}' class = '{new_class}'\n")

            seg = ida_segment.get_next_seg(seg.start_ea)

        idaapi.msg("[MarvelReclass] Segment reclassification complete.\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        pass

    def term(self):
        idaapi.msg("[MarvelReclass] Plugin terminated.\n")


def PLUGIN_ENTRY():
    return MarvelReclass()