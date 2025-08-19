import angr, claripy
import archinfo
import logging

def get_z3_for_machine_code_arm64(code, load_addr=0, regs_to_init_dict={}, verbose=False):
    if not verbose:
        logging.getLogger('angr').setLevel('FATAL')
    regs_to_init_dict = regs_to_init_dict if regs_to_init_dict != {} else {"pc": claripy.BVV(0, 64)}
    byte_mc_code = preprocess_mc(code, False, 4)
    jump_instr=[0x000056e3.to_bytes(4, byteorder="little"),  0xffffff0a.to_bytes(4, byteorder="little")]
    project, state = init_project(byte_mc_code, archinfo.ArchAArch64(), load_addr, jump_instr, len(byte_mc_code) * 4, 4)
    init_regs = init_registers_blank(regs_to_init_dict, state, archinfo.ArchAArch64(), verbose=verbose)
    concrete_init_regs = init_registers_concrete(regs_to_init_dict, state, archinfo.ArchAArch64(), verbose=verbose)
    init_regs.update(concrete_init_regs)
    init_mem = state.memory
    res_regs, res_mem = step_bb_ret_regs_and_mem(project, state, "r6", archinfo.ArchAArch64(), verbose=verbose)
    if res_regs == None and res_mem == None:
        return None, None, None, None
    return res_regs, res_mem, init_regs, init_mem

def get_z3_for_machine_code_rv64(code, load_addr=0, regs_to_init_dict={}, verbose=False):
    if not verbose:
        logging.getLogger('angr').setLevel('FATAL')
    regs_to_init_dict = regs_to_init_dict if regs_to_init_dict != {} else {"pc": claripy.BVV(0, 64)}
    byte_mc_code = preprocess_mc(code, True, 4)
    project, state = init_project(byte_mc_code, archinfo.ArchRISCV64(), load_addr, [0x00060663.to_bytes(4, byteorder="little")], len(byte_mc_code) * 4, 4)
    init_regs = init_registers_blank(regs_to_init_dict, state, archinfo.ArchRISCV64(), verbose=verbose)
    concrete_init_regs = init_registers_concrete(regs_to_init_dict, state, archinfo.ArchRISCV64(), verbose=verbose)
    init_regs.update(concrete_init_regs)
    init_mem = state.memory
    res_regs, res_mem = step_bb_ret_regs_and_mem(project, state, "x12", archinfo.ArchRISCV64(), verbose=verbose)
    if res_regs == None and res_mem == None:
        return None, None, None, None
    return res_regs, res_mem, init_regs, init_mem

def step_bb_ret_regs_and_mem(project, state, branch_reg, arch, verbose=False):
    simulation = project.factory.simulation_manager(state)
    simulation = simulation.step()
    states = simulation.active
    if verbose:
        for regname in list(arch.registers.keys()):
            regval = getattr(states[-1].regs, regname)
            print("step claripy %s register value: %s" % (regname, str(regval)))
    if len(states) == 2:
        assert set(dir(states[-1].regs)) == set(list(arch.registers.keys())) # just a check wheter we really get all registers
        return states[1].regs, states[1].memory # 1 = false
    elif len(states) == 1:
        # case: x12 (rv64) or r5 (arm64) was set to a const by code
        print("found only one state, %s must have been set by code" % branch_reg)
        assert set(dir(states[-1].regs)) == set(list(arch.registers.keys())) # just a check wheter we really get all registers
        return states[0].regs, states[0].memory
    elif len(simulation.errored) > 0:
        for err in simulation.errored:
            print(err)
        return None, None
        assert 0, "error"
    import claripy, archinfo
    for regname in list(archinfo.ArchRISCV64().registers.keys()):
        if claripy.backends.z3.convert(getattr(states[0].regs, regname)).sexpr() != claripy.backends.z3.convert(getattr(states[1].regs, regname)).sexpr():
            print(regname + "\n", claripy.backends.z3.convert(getattr(states[0].regs, regname)).sexpr() + "\n", claripy.backends.z3.convert(getattr(states[1].regs, regname)).sexpr())
    assert 0, "found no/to many successor states"

def init_registers_concrete(mapping, state, arch, verbose=False):
    """ init registers with values, mapping: string -> claripy.BVV/BVS"""
    concrete_regs = {}
    for register, value in mapping.items():
        state.registers.store(register, value)
        if verbose:
            print("init %s with concrete value %s" % (register, str(value)))
        concrete_regs[register] = value
    return concrete_regs

def init_registers_blank(mapping, state, arch,  verbose=False):
    """ init registers with abstract bvs """
    init_regs = {}
    assert set(dir(state.regs)) == set(list(arch.registers.keys())) # just a check wheter we really get all registers
    for regname, size in arch.registers.items():# TODO: aliasing should be ok?
        if regname in mapping: continue
        val =  claripy.BVS(regname, size[1] * 8)
        if verbose:
            print("init %s with %d-bit bv %s" % (regname, size[1] * 8, str(val)))
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

def init_project(asm, arch, load_Addr, jump_instr, jump_load_addr, code_size=4):
    project = angr.load_shellcode(asm[0], arch=arch, start_offset=load_Addr,
                                   load_address=load_Addr, selfmodifying_code=True,
                                   thumb=False)
    entry_state = project.factory.entry_state(add_options= {
        #angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        #angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        #angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        #angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    })
    for i, instr in enumerate(jump_instr):
        entry_state.memory.store(jump_load_addr + i * code_size * 8, instr)
    return project, entry_state

def create_input_string_bvs(num):
    input_chars = [claripy.BVS("char_%d" % i, 8) for i in range(num)]
    input = claripy.Concat(*input_chars)
    return input, input_chars

def add_constraints_to_solver(constraints, entry_state):
    for constrs in constraints:
        entry_state.solver.add(*constrs)
