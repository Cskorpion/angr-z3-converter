import claripy, archinfo
from angrsmtdump import gen_archs

PY2_EXECUTION_CLASS = """class Execution(object):
    def __init__(self, code, arch, init_regs, init_mem, res_regs, res_mem, load_addr):
        self.code = code
        self.arch = arch
        self.init_registers = init_regs
        self.init_memory = init_mem
        self.result_reg_values = res_regs
        self.result_memory_values = res_mem 
        self.load_addr = load_addr"""

def dump_executions(executions, filename):
    with open(filename, "w") as outfile:
        outfile.write(dump_all_arch_class_str())
        outfile.write("\n\n")
        #outfile.write("from decompile.Execution import Execution\n")
        outfile.write(PY2_EXECUTION_CLASS)
        outfile.write("\n\n")
        outfile.write("executions = []\n\n")
        for i, execution in enumerate(executions):
            outfile.write(execution.to_py2(str(i)))
            outfile.write("\n")
            outfile.write("executions.append(_" + str(i) + "_Execution)\n\n")

def dump_code(code, filename, verbose=False):
    with open(filename, "w") as outfile:
        outfile.write("code = [")
        for i, instr in enumerate(code):
                outfile.write("%d," % instr[0])
        outfile.write("]")

def dump_all_arch_class_str():
    """ archinfo is missing rv64 on py2"""
    s = [gen_archs.STR_ArchRISCV64]
    #s.append(gen_archs.ArchAArch64)
    return "\n".join(s)

def extract_all_regs_mem(res_regs , res_mem,  init_regs, init_mem, arch, verbose=False):
    if None in (res_regs , res_mem,  init_regs, init_mem, arch):
        return res_regs , res_mem,  init_regs, init_mem
    return extract_registers(res_regs, arch), extract_memory(res_mem, []), extract_registers(init_regs, arch), extract_memory(init_mem, [])

def extract_registers(registers, arch):
    z3_regs = {}
    if isinstance(registers, dict):
        for regname in list(arch.registers.keys()):
            z3_regs[regname] = claripy.backends.z3.convert(registers[regname]).sexpr()
    else:
        for regname in list(arch.registers.keys()):
            z3_regs[regname] = claripy.backends.z3.convert(getattr(registers, regname)).sexpr()
    return z3_regs

def extract_memory(memory, addrs):
    # TODO: 
    z3_mem = {}
    #for regname in list(arch.registers.keys()):
    #    z3_regs[regname] = claripy.backends.z3.convert(getattr(registers, regname)).sexpr()
    return z3_mem 

class Execution(object):

    def __init__(self, code, arch, init_regs, init_mem, res_regs, res_mem, load_addr):
        self.code = code
        self.arch = arch
        self.init_registers = init_regs
        self.init_memory = init_mem
        self.result_reg_values = res_regs
        self.result_memory_values = res_mem 
        self.load_addr = load_addr
        self.broken =  None in (res_regs , res_mem,  init_regs, init_mem, arch)

    def to_py2(self, pref=""):
        if self.broken: return "\'Broken\’\n"
        code = []
        pref = "_" + pref
        code.append(pref + "_code = %s " % str(self.code))
        code.append(pref + "_arch = %s() " % str(type(archinfo.ArchRISCV64())).split(".")[-1][:-2])

        code.append(pref + "_init_registers = %s " %  str(self.init_registers))
        code.append(pref + "_init_memory = %s " % str(self.init_memory))
        
        code.append(pref + "_result_reg_values = %s " % str(self.result_reg_values)),
        code.append(pref + "_result_memory_values = %s " % str(self.result_memory_values))

        code.append(pref + "_load_addr = %s " % str(self.load_addr))
        code.append(pref + "_Execution =  Execution(%s,%s,%s,%s,%s,%s,%s)" 
                    % (pref + "_code", pref + "_arch", pref + "_init_registers",
                        pref + "_init_memory", pref + "_result_reg_values" ,
                          pref + "_result_memory_values", pref + "_load_addr"))
        return "\n".join(code)