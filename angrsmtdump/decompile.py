import angr, claripy
import archinfo
import logging

def get_z3_for_machine_code_arm64(code, load_addr=0, regs_to_init_dict={}, usepypcode=False, verbose=False):
    if not verbose:
        logging.getLogger('angr').setLevel('FATAL')
    regs_to_init_dict = regs_to_init_dict if regs_to_init_dict != {} else {"pc": claripy.BVV(0, 64)}
    if usepypcode:
        arch = archinfo.ArchPcode("AARCH64:LE:64:v8A")
        ncode = code + [0xFF0011EB, 0x00040054] # CMP X7, X17 ; BEQ #128
        byte_mc_code = preprocess_mc_arm64_pcode(ncode, False, 4)
        pcode = translate_to_pcode(byte_mc_code, "AARCH64:LE:64:v8A",True) 
        project, state = init_project_pcode(byte_mc_code, arch, load_addr)
    else:
        arch = archinfo.ArchAArch64()
        byte_mc_code = preprocess_mc_arm64(code, False, 4)
        jump_instr=[0xFF0011EB.to_bytes(4, byteorder="little"),  0x00040054.to_bytes(4, byteorder="little")] # 0x000056e3 0xffffff0a
        project, state = init_project(byte_mc_code, arch, load_addr, jump_instr, len(byte_mc_code) * 4, 4)
    init_regs = init_registers_blank(regs_to_init_dict, state, arch, verbose=verbose)
    concrete_init_regs = init_registers_concrete(regs_to_init_dict, state, arch, verbose=verbose)
    init_regs.update(concrete_init_regs)
    init_mem = state.memory
    activestate, res_regs, res_mem = step_bb_ret_regs_and_mem(project, state, "r6", arch, verbose=verbose)
    if res_regs == None and res_mem == None:
        return None, None, None, None, None
    return activestate, res_regs, res_mem, init_regs, init_mem

def get_z3_for_machine_code_rv64(code, load_addr=0, regs_to_init_dict={}, branch_instr=0x09138063, usepypcode=False, verbose=False):
    if not verbose:
        logging.getLogger('angr').setLevel('FATAL')
    regs_to_init_dict = regs_to_init_dict if regs_to_init_dict != {} else {"pc": claripy.BVV(0, 64)}
    if usepypcode:
        arch = archinfo.ArchPcode("RISCV:LE:64:RV64G")
        ncode = code + [branch_instr]  # was previously 0x00060663
        byte_mc_code, num_bytes = preprocess_mc_rv64_pcode(ncode, True)
        project, state = init_project_pcode(byte_mc_code, arch, 0)
    else:
        arch = archinfo.ArchRISCV64()
        byte_mc_code, num_bytes = preprocess_mc_rv64(code, True)
        project, state = init_project(byte_mc_code, arch, load_addr, [branch_instr.to_bytes(4, byteorder="little")], num_bytes, 4)
    init_regs = init_registers_blank(regs_to_init_dict, state, arch, verbose=verbose)
    concrete_init_regs = init_registers_concrete(regs_to_init_dict, state, arch, verbose=verbose)
    init_regs.update(concrete_init_regs)
    init_mem = state.memory
    activestate, res_regs, res_mem = step_bb_ret_regs_and_mem(project, state, "x12", arch, verbose=verbose)
    if res_regs == None and res_mem == None:
        print("error %s" % str(code))
        return None, None, None, None, None
    return activestate, res_regs, res_mem, init_regs, init_mem

def step_bb_ret_regs_and_mem(project, state, branch_reg, arch, verbose=False):
    simulation = project.factory.simulation_manager(state)
    simulation = simulation.step()
    states = simulation.active
    if verbose:
        assert len(states) > 0, "found no states"
        for regname in list(arch.registers.keys()):
            if "hpmcounter" in regname or "csr" in regname: continue # rv64: dont write like all 64464554757 registers into stdout # usually interrested in x1-x31
            regval = getattr(states[-1].regs, regname)
            print("step claripy %s register value: %s" % (regname, str(regval)))
    if len(states) == 2:
        assert set(dir(states[-1].regs)) == set(list(arch.registers.keys())) # just a check wheter we really get all registers
        return states[1], states[1].regs, states[1].memory # 1 = false
    elif len(states) == 1:
        # case: x12 (rv64) or r5 (arm64) was set to a const by code
        print("found only one state, %s must have been set by code" % branch_reg)
        assert set(dir(states[0].regs)) == set(list(arch.registers.keys())) # just a check wheter we really get all registers
        return states[0], states[0].regs, states[0].memory
    elif len(simulation.errored) > 0:
        for err in simulation.errored:
            print(err)
        return None, None, None
        assert 0, "error"
    elif len(states) == 0:
        assert 0, "found no states"
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
        if verbose and False:
            print("init %s with %d-bit bv %s" % (regname, size[1] * 8, str(val)))
        state.registers.store(regname, val)
        init_regs[regname] = val

    return init_regs 

def translate_to_pcode(code, pcode_arch, verbose=False):
    from pypcode import Context

    ctx = Context(pcode_arch)

    pcode = ctx.translate(code)

    if verbose:
        print("pcode:\n %s" %str(pcode))

    return pcode

def preprocess_mc_arm64_pcode(code, little_endian, opcode_size=4):
    """ turn int opcodes into bytes """
    if not isinstance(code, list): 
        code = [code]
    #assert len(code) == 1, "multiple instructions not allowed yet"
    val = code[0]
    if len(code) == 1: return val.to_bytes(opcode_size, byteorder="little" if little_endian else "big")
    for i in range(1, len(code)):
        val = val << opcode_size * 8
        val += code[i]
    #from pypcode import Context
    #ctx = Context("AARCH64:LE:64:v8A")
    #dx = ctx.translate(val.to_bytes(opcode_size * len(code), byteorder="little" if little_endian else "big"))
    #print(dx)
    return val.to_bytes(opcode_size * len(code), byteorder="little" if little_endian else "big")


def preprocess_mc_rv64_pcode(code, little_endian):
    """ turn int opcodes into bytes """
    if not isinstance(code, list): 
        code = [code]
    #assert len(code) == 1, "multiple instructions not allowed yet"
    val = code[-1]
    if len(code) == 1: 
        if val & 0b11 == 0b11:
            return val.to_bytes(4, byteorder="little" if little_endian else "big")
        else:
            return val.to_bytes(2, byteorder="little" if little_endian else "big")
    num_bytes = 4 if (val & 0b11 == 0b11) else 2
    for i in range(2, len(code) + 1):
        opcodesize = 4 if (code[-i] & 0b11 == 0b11) else 2
        val = val << (opcodesize * 8)
        num_bytes += opcodesize
        val += code[-i]
        #print("bytes: " + str(val.to_bytes(num_bytes, byteorder="little" if little_endian else "big")))
    #from pypcode import Context
    #ctx = Context("RISCV:LE:64:RV64G")
    #dx = ctx.translate(val.to_bytes(num_bytes, byteorder="little" if little_endian else "big"))
    #print(dx)
    return val.to_bytes(num_bytes, byteorder="little" if little_endian else "big"), num_bytes


def preprocess_mc_arm64(code, little_endian, opcode_size=4):
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

def preprocess_mc_rv64(code, little_endian):
    """ turn int opcodes into bytes """
    if not isinstance(code, list): 
        code = [code]
    assert len(code) == 1, "multiple instructions not allowed yet"
    byte_mc_code = []
    numbytes = 0
    for instr in code:
        if isinstance(instr, int):
            if instr & 0b11 == 0b11:
                byte_mc_code.append(instr.to_bytes(4, byteorder="little" if little_endian else "big"))
                numbytes += 4
            else:
                #compressed
                byte_mc_code.append(instr.to_bytes(2, byteorder="little" if little_endian else "big"))
                numbytes += 2
        elif isinstance(instr, bytes):
            byte_mc_code.append(instr)
        else:
            assert 0, "cant convert opcode from %s to bytes" % str(instr.__class__)
    return byte_mc_code,  numbytes

def init_project_pcode(code, arch, load_Addr):
    project = angr.load_shellcode(code, arch=arch, start_offset=load_Addr,
                                   load_address=load_Addr, selfmodifying_code=True,
                                   thumb=False)
    entry_state = project.factory.entry_state(add_options= {
        #angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        #angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        #angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        #angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    })

    return project, entry_state

def init_project(asm, arch, load_Addr, jump_instr, jump_load_addr, code_size=4):
    """ Jump instruction must be uncompressed """
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