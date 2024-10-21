import idautils
import idaapi
from idc import *
import ida_funcs
import ida_allins
import ida_ua
import idc

var_array = []

for s in idautils.Segments():
    start = idc.get_segm_start(s)
    end = idc.get_segm_end(s)
    name = idc.get_segm_name(s)
#    print(start, end, name)
    for f in Functions(start, end):
        f = ida_funcs.get_func(f)
#        print(f)
        
#        func = []
        distance = 0
        found = False
        for ea in Heads(f.start_ea, f.end_ea):
            inst = idaapi.insn_t()
            if distance > 2:
                distance=0
                func = []
                continue
#            print(inst) 
            length = idaapi.decode_insn(inst, ea)
            if idc.print_insn_mnem(ea) == 'nop' or (idc.print_insn_mnem(ea) == 'xor' and len(print_operand(ea,0)) == 3):
                distance = 0
                pass
            elif inst.itype == ida_allins.NN_mov and inst.ops[1].type == ida_ua.o_imm and inst.ops[0].type == ida_ua.MAKELINE_STACK:
                if not func:
                    func = []
                    start = ea
                    distance = 0
                    
                func.append(inst.ops[1].value)
                distance = 0
            elif idc.print_insn_mnem(ea) == 'xor' and len(print_operand(ea, 0)) == 2 and len(print_operand(ea, 1)) == 2:
#                print("function")
#                print("Mov", inst.ops[1].value)
#                print(hex(ea))
                
#                print([hex(i) for i in func])
                
                meta = {"enc": func, "address": hex(start), 'end': hex(ea)}
                
                found = True
#                print(func)
                
                func = []
            elif idc.print_insn_mnem(ea) == 'xor' and len(print_operand(ea,0)) == 2 and inst.ops[1].type == ida_ua.o_imm:
                if found:
                    meta["key"] = inst.ops[1].value

            elif idc.print_insn_mnem(ea) == 'cmp' and inst.ops[1].type == ida_ua.o_imm:
                if found:
                    meta["len"] = inst.ops[1].value
                    var_array.append(meta)
                    meta = {}
                    found = False
            else:
                distance += 1

for arr in var_array:
    byte_array = bytearray()
    if 'key' in arr and 'enc' in arr and 'len' in arr:
        for dword in arr['enc']:
            byte_array.extend(dword.to_bytes(4, byteorder='little'))
        #print(arr)
        output = []
        for index, byte in enumerate(byte_array[:arr['len']]):
            output.append(chr(byte ^ index ^ 0x4d ^ arr['key']))
        
        joined_string = ''.join(output).replace('\x00', '')
        print(joined_string)
        

