import archinfo
import os
import sys
import subprocess
from angrsmtdump.decompile import get_z3_for_machine_code_rv64, get_z3_for_machine_code_arm64
from angrsmtdump.execution import Execution, dump_executions, extract_all_regs_mem, dump_code

is_pypy = '__pypy__' in sys.builtin_module_names or "pypy" in sys.executable
interpname = "pypy" if is_pypy else "cpy"

def sim_and_dump_arm64(programs, filename=None, verbose=False):
    execs = []
    arch = archinfo.ArchAArch64()
    load_addr = 0
    ctr = 0
    for prog in programs:
        if ctr%10 == 0:
            print("[%s]: angr simulating: %d/%d" % (interpname, ctr, len(programs)))
        ctr += 1
        if verbose:
            print([hex(p) for p in prog])
        res_regs, res_mem, init_regs, init_mem = get_z3_for_machine_code_arm64(prog, load_addr, {}, verbose=verbose) # empty dict -> only pc wil be a constatnt number (0)
        res_regs, res_mem, init_regs, init_mem = extract_all_regs_mem(res_regs , res_mem,  init_regs, init_mem, arch, verbose=verbose)
        exec = Execution(prog, arch, init_regs, init_mem, res_regs, res_mem, load_addr)
        execs.append(exec)
    filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), "executions.py") if filename == None else filename
    dump_executions(execs, filename)

def sim_and_dump_rv64(programs, filename=None, verbose=False):
    execs = []
    arch = archinfo.ArchRISCV64()
    load_addr = 0
    ctr = 0
    for prog in programs:
        if ctr%10 == 0:
            print("[%s]: angr simulating: %d/%d" % (interpname, ctr, len(programs)))
        ctr += 1
        if verbose:
            print([hex(p) for p in prog])
        res_regs, res_mem, init_regs, init_mem = get_z3_for_machine_code_rv64(prog, load_addr, {}, verbose=verbose) # empty dict -> only pc wil be a constatnt number (0)
        res_regs, res_mem, init_regs, init_mem = extract_all_regs_mem(res_regs , res_mem,  init_regs, init_mem, arch, verbose=verbose)
        exec = Execution(prog, arch, init_regs, init_mem, res_regs, res_mem, load_addr)
        execs.append(exec)
    filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), "executions.py") if filename == None else filename
    dump_executions(execs, filename)

def external_sim_and_dump_rv64(programs, filename=None, verbose=False):
    assert "CPY3ANGR" in os.environ, str(os.environ)#"cant find cpy3 with angr in environment " 
    cmd = [os.environ["CPY3ANGR"], "-m", "angrsmtdump", "-arch", "rv64", "-file", filename]
    if verbose: cmd.append("-verbose")
    cmd.append("-opcodes")
    cmd.append(str(" ".join([str(p[0]) for p in programs])))
    subprocess.check_call(" ".join(cmd), shell=True)
