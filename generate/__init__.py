from generate.pydrofoil_hypothesis import generate_machine_code_rv64, generate_machine_code_randint_rv64, generate_machine_code_names_randint_rv64

def gen_rv64_code(num_ops, verbose=False, allowed_instrs=None):
    return generate_machine_code_randint_rv64(num_ops, verbose=verbose, allowed_instrs=allowed_instrs)

def gen_rv64_code_names(num_ops, verbose=False, allowed_instrs=None):
    return generate_machine_code_names_randint_rv64(num_ops, verbose=verbose, allowed_instrs=allowed_instrs)

