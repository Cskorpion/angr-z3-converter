import _pydrofoil
import hypothesis, pydrofoilhypothesis

# partially copied from https://github.com/Bisasamdude/pydrofoil-hypothesis/blob/main/pydrofoilhypothesis/test/test_examples.py


def generate_machine_code_rv64(num_code=128, verbose=False):
    m = _pydrofoil.RISCV64()
    #print(dict(m.types.ast.sail_type.constructors).keys())
    itype_args = dict(m.types.ast.sail_type.constructors)["ITYPE"]
    itype_args_strategy = pydrofoilhypothesis.hypothesis_from_pydrofoil_type(itype_args, m)

    code = []

        #strategies list
    #hypothesis.example()

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