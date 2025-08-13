from generate.pydrofoil_hypothesis import generate_machine_code_rv64


def test_generate_code_rv64():

    codes = generate_machine_code_rv64(384)

    assert len(codes) == 384
    
    for code in codes:
        assert len(code) == 1
        assert isinstance(code[0], int)
