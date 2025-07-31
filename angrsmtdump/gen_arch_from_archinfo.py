import archinfo

def gen(archs, outfile):
    to_write = []
    for archname in archs:
        print("gen %s" % archname)
        assert hasattr(archinfo, archname)
        arch = getattr(archinfo, archname)()
        s = ["class %s():" % archname]
        s.append("    def __init__(self):") 
        s.append("        self.bits = %d" % arch.bits) 
        s.append("        self.memory_endness  = \"%s\" " % ("LE" if arch.memory_endness == archinfo.Endness.LE else "BE"))
        s.append("        self.register_endness  = \"%s\" " % ("LE" if arch.register_endness == archinfo.Endness.LE else "BE"))
        s.append("        self.instruction_endness  = \"%s\" " % ("LE" if arch.instruction_endness == archinfo.Endness.LE else "BE"))
        s.append("        self.registers_size = %s " % str({k:v[1] for k,v in arch.registers.items()}))
        s.append("        self.register_aliases = %s " % str({reg.name:[an for an in reg.alias_names] for reg in arch.register_list}))
        arch_string = "\n".join(s)
        to_write.append("STR_%s = \"\"\"%s\"\"\"\n\n" % (archname, arch_string))
        to_write.append("%s\n\n" % arch_string)

    with open(outfile, "w") as file:
        for s in to_write:
            file.write(s)
        
if __name__ == "__main__":
    import sys, os, angrsmtdump
    file =  os.path.join(os.path.dirname(os.path.abspath(angrsmtdump.__file__)), "gen_archs.py")
    gen(sys.argv[1:], file)