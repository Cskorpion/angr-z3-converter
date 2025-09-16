import _pydrofoil
import hypothesis, pydrofoilhypothesis
import random, os

# partially copied from https://github.com/Bisasamdude/pydrofoil-hypothesis/blob/main/pydrofoilhypothesis/test/test_examples.py

ALLOWED_RV64_INSTR_NAMES = ["ITYPE", "UTYPE", "RTYPE", "SHIFTIOP", "ADDIW", "RTYPEW", "SHIFTIWOP", "C_ADDI",
                            "C_ADDI16SP", "C_LUI", "C_SRLI", "LOAD"] # STORE  "BTYPE", "RISCV_JAL"
DISALLOWED_RV64_INSTR_NAMES = ["ZBS_RTYPE", "ZICOND_RTYPE", "C_ADDI4SPN","C_ADDIW","C_ADDI_HINT",
                               "C_LUI_HINT", "C_SRLI_HINT"]

CODEFILE = os.path.join("/home/christophj/Dokumente/Uni/Projektarbeit/angr-z3-converter/" "code.txt")

def get_argstrategy_constructor():
    m = _pydrofoil.RISCV64()

    types = []

    itype_args = dict(m.types.ast.sail_type.constructors)["ITYPE"]
    itype_args_strategy = pydrofoilhypothesis.hypothesis_from_pydrofoil_type(itype_args, m)
    types.append((itype_args_strategy, m.types.ITYPE))

    utype_args = dict(m.types.ast.sail_type.constructors)["UTYPE"]
    utype_args_strategy = pydrofoilhypothesis.hypothesis_from_pydrofoil_type(utype_args, m)
    types.append((utype_args_strategy, m.types.UTYPE))

    rtype_args = dict(m.types.ast.sail_type.constructors)["RTYPE"]
    rtype_args_strategy = pydrofoilhypothesis.hypothesis_from_pydrofoil_type(rtype_args, m)
    types.append((rtype_args_strategy, m.types.RTYPE))

    shiftiop_args = dict(m.types.ast.sail_type.constructors)["SHIFTIOP"]
    shiftiop_args_strategy = pydrofoilhypothesis.hypothesis_from_pydrofoil_type(shiftiop_args, m)
    types.append((shiftiop_args_strategy, m.types.SHIFTIOP))

    addiw_args = dict(m.types.ast.sail_type.constructors)["ADDIW"]
    addiw_args_strategy = pydrofoilhypothesis.hypothesis_from_pydrofoil_type(addiw_args, m)
    types.append((addiw_args_strategy, m.types.ADDIW))

    rtypew_args = dict(m.types.ast.sail_type.constructors)["RTYPEW"]
    rtypew_args_strategy = pydrofoilhypothesis.hypothesis_from_pydrofoil_type(rtypew_args, m)
    types.append((rtypew_args_strategy, m.types.RTYPEW))

    shiftiopw_args = dict(m.types.ast.sail_type.constructors)["SHIFTIWOP"]
    shiftiopw_args_strategy = pydrofoilhypothesis.hypothesis_from_pydrofoil_type(shiftiopw_args, m)
    types.append((shiftiopw_args_strategy, m.types.SHIFTIWOP))

    return types


def generate_machine_code_randint_rv64_str(num_code=128, verbose=False):
    m = _pydrofoil.RISCV64()
    code = set()

    while(len(code)) < num_code:
        opcode = random.randint(0, 2**32)
        instruction = m.lowlevel.encdec_backwards(opcode)
        instr_name = str(instruction)
        if "ILLEGAL" in instr_name: 
            instruction = m.lowlevel.encdec_compressed_backwards(opcode)
            instr_name = str(instruction)
            if "C_LUI" in instr_name: 
                if "bitvector(5, 0b00000)" in instr_name: continue # quick fix for x0 as target in CLUI
            if "ILLEGAL" in instr_name: continue
            opcode &= 0b1111111111111111
        ok = False
        for ai in ALLOWED_RV64_INSTR_NAMES:
            if instr_name.startswith(ai): ok = True
            for di in DISALLOWED_RV64_INSTR_NAMES:
                if instr_name.startswith(di): ok = False
            if ok:
                if verbose: print(hex(opcode), instr_name)
                code.add(str(instruction))

    return [[c] for c in list(code)]


def generate_machine_code_randint_rv64(num_code=128, verbose=False):
    m = _pydrofoil.RISCV64()
    code = set()

    while(len(code)) < num_code:
        opcode = random.randint(0, 2**32)
        instruction = m.lowlevel.encdec_backwards(opcode)
        instr_name = str(instruction)
        if "ILLEGAL" in instr_name: 
            instruction = m.lowlevel.encdec_compressed_backwards(opcode)
            instr_name = str(instruction)
            if "C_LUI" in instr_name: 
                if "0b00000" in instr_name: continue # quick fix for x0 as target in CLUI
            if "ILLEGAL" in instr_name: continue
            opcode &= 0b1111111111111111
        ok = False
        for ai in ALLOWED_RV64_INSTR_NAMES:
            if instr_name.startswith(ai): ok = True
            for di in DISALLOWED_RV64_INSTR_NAMES:
                if instr_name.startswith(di): ok = False
            if ok:
                if verbose: print(hex(opcode), instr_name)
                code.add(opcode)
    codelist = [[c] for c in list(code)]
    
    _sync_dump_append_opcodes(codelist, CODEFILE)

    return codelist



def __generate_machine_code_rv64(num_code=128, verbose=False):
    m = _pydrofoil.RISCV64()

    types = get_argstrategy_constructor()

    code = []
    
    num_types = len(types)

    for i in range(num_types * 3):

        @hypothesis.given(types[i%num_types])
        def gen(args):
            instruction = m.types.ITYPE(*args)
            if str(instruction).startswith("C_"):
                #bits = m.lowlevel.encdec_compressed_forwards(instruction)
                return
            else:
                bits = m.lowlevel.encdec_forwards(instruction)
            code.append([bits.unsigned()])
        gen()

    random_max = len(code) - 1
    return [code[random.randint(0, random_max)] for _ in range(num_code)]


def generate_machine_code_rv64(num_code=128, verbose=False):
    m = _pydrofoil.RISCV64()

    types = get_argstrategy_constructor()

    code = []
    
    seen = set()

    while len(code) < num_code:
        index  = random.randint(0, len(types) - 1)

        args = hypothesis.find(types[index][0], lambda x: x not in seen)

        instruction = types[index][1](*args)

        if str(instruction).startswith("C_"):
            continue

        bits = m.lowlevel.encdec_forwards(instruction)
        code.append([bits.unsigned()])
        seen.add(args)
    
    return code


def generate_machine_code_rv64_str(num_code=128, verbose=False):
    m = _pydrofoil.RISCV64()

    types = get_argstrategy_constructor()

    code = []
    
    seen = set()

    while len(code) < num_code:
        index  = random.randint(0, len(types) - 1)

        args = hypothesis.find(types[index][0], lambda x: x not in seen)

        instruction = types[index][1](*args)

        if str(instruction).startswith("C_"): continue

        code.append(str(instruction))
        seen.add(args)
    
    return code

def _generate_machine_code_rv64(num_code=128, verbose=False):
    m = _pydrofoil.RISCV64()

    itype_args = dict(m.types.ast.sail_type.constructors)["ITYPE"]
    itype_args_strategy = pydrofoilhypothesis.hypothesis_from_pydrofoil_type(itype_args, m)

    code = []


    @hypothesis.given(itype_args_strategy)
    @hypothesis.settings(max_examples=num_code)
    def gen(args):
        instruction = m.types.ITYPE(*args)
        if str(instruction).startswith("C_"):
            #bits = m.lowlevel.encdec_compressed_forwards(instruction)
            return
        else:
            bits = m.lowlevel.encdec_forwards(instruction)
        code.append([bits.unsigned()])

    while len(code) < num_code:
        gen()
    
    return code[:num_code]
    


def _sync_dump_append_opcodes(codes, outfilename):
    from filelock import FileLock
    import time
    #print(outfilename)
    fl = FileLock(outfilename + ".lock")
    while True:
        #print("trying to acquire lock %s" % str(time.time()))
        try:
            olock = fl.acquire(0.5,poll_interval=0.1)
            #print("lock acquired %s" % str(time.time()))
            with open(outfilename, "a") as ofile:
                for code in codes:
                    ofile.write("%s\n"  % str(code[0]))
            fl.release(True)
            #print("lock released %s" % str(time.time()))
            return
        except TimeoutError:
            pass
            #print("didnt acquire lock :(")
        #print("waiting for lock %s" % str(time.time()))


"""
    num_todo = num_code

    while num_todo != 0:
        liststrat = hypothesis.strategies.lists(itype_args_strategy, min_size=num_todo, max_size=num_todo)
        arglist = hypothesis.find(liststrat, lambda x: True)

        for args in arglist:
            instruction = m.types.ITYPE(*args)
            if str(instruction).startswith("C_"):
                #bits = m.lowlevel.encdec_compressed_forwards(instruction)
                continue
            else:
                bits = m.lowlevel.encdec_forwards(instruction)
                print(bits)
            code.append([bits.unsigned()])
        
        num_todo = num_code - len(code)
        
    return code

"""