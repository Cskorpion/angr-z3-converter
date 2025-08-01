import os
import angrsmtdump
from angrsmtdump.decompile import get_z3_for_machine_code_rv64
from angrsmtdump import sim_and_dump_rv64

def test_load_angr_simple():
    res_regs, res_mem, init_regs, init_mem = get_z3_for_machine_code_rv64(0x07300613, 0, {})
    assert "+" in str(res_regs.x12)
    assert "0x73" in str(res_regs.x12)

def test_complete():
    code = [
        [0x07300613], # li   x12 x0  115
        [0x003f71b3], # and  x3  x30 x3
        [0x03f71a13], # slli x20 x14 63 slli by 115 is ileagal = 0x07371a13
        [0x3e804093], # xori x1  x0 1000
        [0x00000013], # nop = addi x0 x0 0
        [0x0ff0000f], # fence
        [0x04d3e893], # ori  x17 x7 77 
    ]

    sim_and_dump_rv64(code)

    file =  os.path.join(os.path.dirname(os.path.abspath(angrsmtdump.__file__)), "executions.py")
    assert os.path.exists(file)

    from angrsmtdump.executions import executions

    assert "decompile.executions.ArchRISCV64" in str(executions[0].arch.__class__)

    assert executions[0].code == code[0]

    assert executions[0].init_registers["pc"].endswith("000000")