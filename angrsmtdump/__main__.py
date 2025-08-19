import sys
from angrsmtdump import sim_and_dump_rv64, external_sim_and_dump_rv64, dump_code

if __name__ ==  "__main__":
    outfile = None
    arch = None
    num_ops = None
    opcodes = None
    verbose = False
    use_cpy_for_angr = False
    only_generate = False
    i = 1
    print(sys.argv)
    if len(sys.argv) < 7:
        print("must provide: -arch arch -file file -numops numops")
        print("e.g. python -m angrsmtdump -arch rv64 -file out.py -numops 128")
        print("or python -m angrsmtdump -arch rv64 -file out.py -opcodes 25 2727627795 120587795 ...")
    while i < len(sys.argv):
        if sys.argv[i] == "-arch":
            arch = sys.argv[i+1]
        elif sys.argv[i] == "-file":
            outfile = sys.argv[i+1]
        elif sys.argv[i] == "-numops":
            num_ops = int(sys.argv[i+1])
        elif sys.argv[i] == "-opcodes":
            opcodes = [[int(x)] for x in sys.argv[i+1:]]
            break
        elif sys.argv[i] == "-verbose":
            verbose = True
            i += 1
            continue
        elif sys.argv[i] == "-angrcpy":
            use_cpy_for_angr = True
            i += 1
            continue
        elif sys.argv[i] == "-generate":
            only_generate = True
            i += 1
            continue
        else:
            assert 0, "invalid args"
        i += 2
    
    assert (opcodes == None) ^ (num_ops == None) , "either generate opcodes or provide them with -opcodes "

    if arch == "rv64":
        if opcodes == None:
            from generate import gen_rv64_code
            opcodes = gen_rv64_code(num_ops, verbose=verbose)
            if only_generate: 
                dump_code(opcodes, outfile, verbose=verbose)
                sys.exit(0)
        if use_cpy_for_angr and '__pypy__' in sys.builtin_module_names:
            external_sim_and_dump_rv64(opcodes, outfile, verbose=verbose)
        else:
            sim_and_dump_rv64(opcodes, outfile, verbose=verbose)
    else:
        assert 0, "unsupported arch %s" % arch