import os
import angrsmtdump
import subprocess
import pytest
import tempfile
from angrsmtdump.decompile import get_z3_for_machine_code_rv64
from angrsmtdump import sim_and_dump_rv64, sim_and_dump_arm64

def test_load_angr_simple():
    state, res_regs, res_mem, init_regs, init_mem = get_z3_for_machine_code_rv64(0x07300613, 0, {}, False, False)
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

    assert "angrsmtdump.executions.ArchRISCV64" in str(executions[0].arch.__class__)

    assert executions[0].code == code[0]

    assert executions[0].init_registers["pc"].endswith("000000")


def test_complete_pcode():
    code = [
        [0x07300613], # li   x12 x0  115
        [0x003f71b3], # and  x3  x30 x3
        [0x03f71a13], # slli x20 x14 63 slli by 115 is ileagal = 0x07371a13
        [0x3e804093], # xori x1  x0 1000
        [0x00000013], # nop = addi x0 x0 0
        [0x0ff0000f], # fence
        [0x04d3e893], # ori  x17 x7 77 
    ]

    sim_and_dump_rv64(code, usepypcode=True)

    file =  os.path.join(os.path.dirname(os.path.abspath(angrsmtdump.__file__)), "executions.py")
    assert os.path.exists(file)

    from angrsmtdump.executions import executions

    assert "angrsmtdump.executions.ArchRISCV64" in str(executions[0].arch.__class__)

    assert executions[0].code == code[0]

    assert executions[0].init_registers["pc"].endswith("000000")

def test_run_subprocess():
    file =  os.path.join(os.path.dirname(os.path.abspath(__file__)), "executions.py")
    cmd = [os.environ["PYDROFOILANGR"], "-m", "angrsmtdump", "-arch", "rv64", "-file", file, "-opcodes", str(" ".join([str(267386895)]))]
    subprocess.check_call(" ".join(cmd),shell=True)

    assert os.path.exists(file)

    from angrsmtdump.test.executions import executions

    assert len(executions) == 1

    assert executions[0].code == [267386895]
    assert executions[0].init_registers["pc"] == "#x0000000000000000"

def test_debug_reg_50():
    import claripy
    state, res_regs, res_mem, init_regs, init_mem = get_z3_for_machine_code_rv64(0xff44c13, 0, {}, False, True) #xori x24, x8, 255
    assert not "reg_50" in str(res_regs.x24)


def test_find_reference_error_rv64():
    from generate import generate_machine_code_rv64
    import tempfile

    print("generate code")
    code = generate_machine_code_rv64(64, True)

    #file = os.path.join(os.path.dirname(os.path.abspath(angrsmtdump.__file__)), "dummy.py")
    file = tempfile.NamedTemporaryFile()

    print("simulate code")
    sim_and_dump_rv64(code, file.name, False)

    file.close()


def test_find_reference_error_arm():
    import tempfile

    print("generate code")

    ## what  pyvex.lift(0x200018b.to_bytes(4,byteorder="big"), 0x1000, archinfo.ArchAArch64()).pp() => ok
    ## wh    pyvex.lift(0x200018b.to_bytes(4,byteorder="little"), 0x1000, archinfo.ArchAArch64()).pp() => error
    ## ??
    code = [
        [0x212280D2],# mov x1, #0x111 dc
        #[0x0200018b],# add x2, x0, x1
        #[0x212280D2],
        #[0x212280D2],
        #[0x212280D2],
        #[0x212280D2],
        #[0x212280D2]
    ]

    #file = os.path.join(os.path.dirname(os.path.abspath(angrsmtdump.__file__)), "dummy.py")
    file = tempfile.NamedTemporaryFile()

    print("simulate code")
    sim_and_dump_arm64(code, file.name, usepypcode=False, verbose=True)

    file.close()
 
def test_generate_and_simulate_pcode_rv64():
    from generate import generate_machine_code_rv64

    print("generate code")
    code = generate_machine_code_rv64(64, True)

    #file = os.path.join(os.path.dirname(os.path.abspath(angrsmtdump.__file__)), "dummy.py")
    file = tempfile.NamedTemporaryFile()

    print("simulate code")
    sim_and_dump_rv64(code, file.name, True, False)

    file.close()

def test_weird_formula():
    # addiw x6, x19, 2009
    code = [[0x7d99831b]]

    file = tempfile.NamedTemporaryFile()

    state, _, _, _, _ = get_z3_for_machine_code_rv64([0x7d99831b], 0, {}, False, True)

    import claripy, z3
    x6val = z3.simplify(claripy.backends.z3.convert(getattr(state.regs, "x6"))).sexpr()

    smtfile = os.path.join(os.path.dirname(os.path.abspath(angrsmtdump.__file__)), "smt.txt")
    with open(smtfile, "w") as ofile:
        ofile.write(x6val)

    import pdb; pdb.set_trace()

    assert not "[" in  x6val
    #sim_and_dump_rv64(code, file.name, False, True)

    file.close()
    assert 0


def test_clui_x0_not_allowed():
    
    file = tempfile.NamedTemporaryFile()

    state, _, _, _, _ = get_z3_for_machine_code_rv64([24669], 0, {}, False, True)

    file.close()
    assert 0