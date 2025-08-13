import sys
from angrsmtdump import sim_and_dump_rv64
from generate import gen_rv64_code

if __name__ ==  "__main__":
    outfile = None
    arch = None
    num_ops = None
    opcodes = None
    i = 1
    print(sys.argv)
    if len(sys.argv) < 7:
        print("must provide: -arch arch -file file -numops numops")
        print("e.g. python -m angrsmtdump -arch rv64 -file out.py -numops 128")
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
        else:
            assert 0, "wrong args"
        i += 2
    
    assert (opcodes == None) ^ (num_ops == None) , "either generate opcodes or provide with -opcodes "

    if arch == "rv64":
        if opcodes == None:
            opcodes = gen_rv64_code(num_ops)
        sim_and_dump_rv64(opcodes, outfile)
    else:
        assert 0, "unsupported arch %s" % arch