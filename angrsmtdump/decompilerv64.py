import sys
from angrsmtdump import sim_and_dump_rv64

if __name__ ==  "__main__":
    outfile = sys.argv[1]
    print(sys.argv)
    code  = None
    if  sys.argv[2] == "-file":
        with open(sys.argv[3],  "r") as infile:
            code = [[int(line, base = 16 if line.startswith("0x") else 10)] for line in infile.readlines()]
    elif sys.argv[2] == "-arg":
        code = [[int(line, base = 16 if line.startswith("0x") else 10)] for line in sys.argv[3:]]
    else:
        print("either call 'python -m decompilerv64 out_filename -file in_filename'")
        print("or call python -m decompilerv64 out_filename -args 0x1232312 0x123445 ...")

    sim_and_dump_rv64(code, outfile)
    