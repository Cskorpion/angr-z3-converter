import archinfo

def gen(archs, p_archs, outfile):
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

    for p_arch in p_archs:
        archname = "ArchPcode_%s_" % p_arch.replace(":", "_")
        print("gen ArchPcode(%s)" % archname)
        assert hasattr(archinfo, "ArchPcode")
        arch = getattr(archinfo, "ArchPcode")(p_arch)
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
    file =  os.path.join(os.path.dirname(__file__), "gen_archs.py")
    archs = ["ArchAArch64", "ArchAMD64", "ArchARM", "ArchARMCortexM", "ArchARMEL", "ArchARMHF", "ArchAVR8",
             "ArchMIPS32", "ArchMIPS64", "ArchPPC32",  "ArchPPC64", "ArchRISCV64", "ArchS390X", "ArchX86"]
    p_archs  = ["RISCV:LE:64:RV64G"]
    gen(archs, p_archs, file)