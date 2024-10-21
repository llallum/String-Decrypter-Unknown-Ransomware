import ida_allins
import ida_ua


inst = idaapi.insn_t()
length = idaapi.decode_insn(inst, here())
type = inst.itype
print(
#print(inst.itype)
#print(dir(inst))


print("arg0")
for i in dir(ida_ua):
    value = getattr(ida_ua, i)
    if value == inst.ops[0].type:
        print(i)

print("arg1")
for i in dir(ida_ua):
    value = getattr(ida_ua, i)
    if value == inst.ops[1].type:
        print(i)

  