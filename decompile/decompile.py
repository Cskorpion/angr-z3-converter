import angr, claripy
import z3
import archinfo
import struct

####   angr on py2   ####
# pip install gitdb2==2.0.6
# pip install future==0.16.0
# pip install cffi==1.7.0
# pip install angr
####   ###########   ####

def get_z3_for_machine_code_rv64(code, load_addr=0, regs_to_init_dict={}):
    regs_to_init_dict = regs_to_init_dict if regs_to_init_dict != {} else {"pc": claripy.BVV(0, 64)}
    byte_mc_code = preprocess_mc(code, True, 4)
    project, state = init_project(byte_mc_code, archinfo.ArchRISCV64(), load_addr, 0x00060663.to_bytes(4, byteorder="little"), len(byte_mc_code) * 4)
    init_regs = init_registers_blank(regs_to_init_dict, state, archinfo.ArchRISCV64())
    concrete_init_regs = init_registers_concrete(regs_to_init_dict, state, archinfo.ArchRISCV64())
    init_regs.update(concrete_init_regs)
    init_mem = state.memory
    res_regs, res_mem = step_bb_ret_regs_and_mem(project, state, "x12")
    return res_regs, res_mem, init_regs, init_mem

def step_bb_ret_regs_and_mem(project, state, branch_reg):
    simulation = project.factory.simulation_manager(state)
    simulation = simulation.step()
    states = simulation.active
    if len(states) == 2:
        #print("exec ok pc:", states[0].regs.pc)
        return states[1].regs, states[1].memory # 1 = false
    elif len(states) == 1:
        # case: x12 was set to a const by code
        #print("exec ok pc:", states[0].regs.pc)
        print("only one state, %s must have been set by code", branch_reg)
        return states[0].regs, states[0].memory
    elif len(simulation.errored) > 0:
        for err in simulation.errored:
            print(err)
        assert 0, "error"
    import claripy, archinfo
    for regname in list(archinfo.ArchRISCV64().registers.keys()):
        if claripy.backends.z3.convert(getattr(states[0].regs, regname)).sexpr() != claripy.backends.z3.convert(getattr(states[1].regs, regname)).sexpr():
            print(regname + "\n", claripy.backends.z3.convert(getattr(states[0].regs, regname)).sexpr() + "\n", claripy.backends.z3.convert(getattr(states[1].regs, regname)).sexpr())
    assert 0, "found no/to many successor states"

def init_registers_concrete(mapping, state, arch):
    """ init registers with values, mapping: string -> claripy.BVV/BVS"""
    concrete_regs = {}
    for register,  value in mapping.items():
        state.registers.store(register, value)
        concrete_regs[register] = value
    return concrete_regs

def init_registers_blank(mapping, state, arch):
    """ init registers with abstract bvs """
    init_regs = {}
    for regname, size in arch.registers.items():# TODO: aliasing should be ok?
        if regname in mapping: continue
        val =  claripy.BVS(regname, size[1] * 8)
        state.registers.store(regname, val)
        init_regs[regname] = val
    return init_regs 
    
def preprocess_mc(code, little_endian, opcode_size=4):
    """ turn int opcodes into bytes """
    if not isinstance(code, list): 
        code = [code]
    assert len(code) == 1, "multiple instructions not allowed yet"
    byte_mc_code = []
    for instr in code:
        if isinstance(instr, int):
            byte_mc_code.append(instr.to_bytes(opcode_size, byteorder="little" if little_endian else "big"))
        elif isinstance(instr, bytes):
            byte_mc_code.append(instr)
        else:
            assert 0, "cant convert opcode from %s to bytes" % str(instr.__class__)
    return byte_mc_code

def init_project(asm, arch, load_Addr, jump_instr, jump_load_addr):
    project = angr.load_shellcode(asm[0], arch=arch, start_offset=load_Addr, load_address=load_Addr, selfmodifying_code=True)
    entry_state = project.factory.entry_state()
    entry_state.memory.store(jump_load_addr, jump_instr)
    return project, entry_state

def create_input_string_bvs(num):
    input_chars = [claripy.BVS("char_%d" % i, 8) for i in range(num)]
    input = claripy.Concat(*input_chars)
    return input, input_chars

def add_constraints_to_solver(constraints, entry_state):
    for constrs in constraints:
        entry_state.solver.add(*constrs)
