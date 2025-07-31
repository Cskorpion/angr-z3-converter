import sys
from angrsmtdump import sim_and_dump_rv64
from generate import gen_rv64_code

if __name__ ==  "__main__":
    outfile = None
    arch = None
    num_ops = None
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
        else:
            assert 0, "wrong args"
        i += 2
    
    if arch == "rv64":
        code = gen_rv64_code(num_ops)
        sim_and_dump_rv64(code, outfile)
    else:
        assert 0, "unsupported arch %s" % arch