import os
import decompile
from decompile.decompile import get_z3_for_machine_code_rv64
from decompile import sim_and_dump_rv64

def test_load_angr_simple():
    res_regs, res_mem, init_regs, init_mem = get_z3_for_machine_code_rv64(0x07300613, 0, {})
    assert "+" in str(res_regs.x12)
    assert "0x73" in str(res_regs.x12)

def test_complete():
    code = [
        [0x07300613], # li   x12 x0  115
        [0x003f71b3], # and  x3  x30 x3
        [0x03f71a13]  # slli x20 x14 63 slli by 115 is ileagal = 0x07371a13
    ]

    sim_and_dump_rv64(code)

    file =  os.path.join(os.path.dirname(os.path.abspath(decompile.__file__)), "executions.py")
    assert os.path.exists(file)

    from decompile.executions import executions

    assert "decompile.executions.ArchRISCV64" in str(executions[0].arch.__class__)

    assert executions[0].code == code[0]

    assert executions[0].init_registers["pc"].endswith("000000")