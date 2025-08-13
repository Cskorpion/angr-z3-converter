import archinfo
import os
from angrsmtdump.decompile import get_z3_for_machine_code_rv64
from angrsmtdump.execution import Execution, dump_executions, extract_all_regs_mem


def sim_and_dump_rv64(programs, filename=None):
    execs = []
    arch = archinfo.ArchRISCV64()
    load_addr = 0
    ctr = 0
    for prog in programs:
        if ctr%10 == 0:
            print("angr simulating: %d/%d" % (ctr, len(programs)))
        ctr += 1
        print([hex(p) for p in prog])
        res_regs, res_mem, init_regs, init_mem = get_z3_for_machine_code_rv64(prog, load_addr, {}) # empty dict -> only pc wil be a constatnt number (0)
        res_regs, res_mem, init_regs, init_mem = extract_all_regs_mem(res_regs , res_mem,  init_regs, init_mem, arch)
        exec = Execution(prog, arch, init_regs, init_mem, res_regs, res_mem, load_addr)
        execs.append(exec)
    filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), "executions.py") if filename == None else filename
    dump_executions(execs, filename)