import _pydrofoil
import hypothesis, pydrofoilhypothesis

# partially copied from https://github.com/Bisasamdude/pydrofoil-hypothesis/blob/main/pydrofoilhypothesis/test/test_examples.py


def generate_machine_code_rv64(num_code=128):
    m = _pydrofoil.RISCV64()
    ast_type = m.lowlevel.encdec_backwards.sail_type.result
    itype_args = dict(m.types.ast.sail_type.constructors)["ITYPE"]
    itype_args_strategy = pydrofoilhypothesis.hypothesis_from_pydrofoil_type(itype_args, m)

    code = []

    @hypothesis.given(itype_args_strategy)
    @hypothesis.settings(max_examples=num_code)
    def gen(args):
        instruction = m.types.ITYPE(*args)
        if str(instruction).startswith("C_"):
            return
            bits = m.lowlevel.encdec_compressed_forwards(instruction)
        else:
            bits = m.lowlevel.encdec_forwards(instruction)
        code.append([bits.unsigned()])

    while len(code) < num_code:
        gen()
    
    return code[:num_code]
    

