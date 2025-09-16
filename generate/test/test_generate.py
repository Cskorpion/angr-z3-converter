from generate.pydrofoil_hypothesis import generate_machine_code_rv64, generate_machine_code_rv64_str, generate_machine_code_randint_rv64_str


def test_generate_code_rv64():

    codes = generate_machine_code_rv64(384)

    assert len(codes) == 384
    
    for code in codes:
        assert len(code) == 1
        assert isinstance(code[0], int)

def test_instr_from_randint_distribution():
    total_instrs = []

    for _ in range(16):
        total_instrs.extend(generate_machine_code_randint_rv64_str(256, True))

    assert len(set(total_instrs)) >= 0.95 * 16 * 256, "%d / %d = %f" % (len(total_instrs), len(set(total_instrs)), len(total_instrs)/(len(set(total_instrs)) * 1.0))
    assert 0

def test_distribution():
    total_instrs = []

    for _ in range(16):
        total_instrs.extend(generate_machine_code_rv64_str(256))

    assert len(set(total_instrs)) >= 0.1 * 16 * 256, "%d / %d = %f" % (len(total_instrs), len(set(total_instrs)), len(total_instrs)/(len(set(total_instrs)) * 1.0))