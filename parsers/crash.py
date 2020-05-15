from parser_util import register_parser, RamParser
from print_out import print_out_str
import local_settings
import os, stat

@register_parser('--crash', 'Generate the script for Red Hat Crash Utility')
class Crash(RamParser):

    def parse(self):
        try:
            crashtool = local_settings.crashtool
        except AttributeError:
            print_out_str("crashtool is missing from local-settings.py")
            crashtool = "crash"

        crashargs = [crashtool]

        kaslr_offset = self.ramdump.get_kaslr_offset()
        if kaslr_offset != 0:
            crashargs.append("--kaslr {0}".format(hex(kaslr_offset)))

        if self.ramdump.kimage_voffset is not None:
            kimagevoff = "kimage_voffset={0}".format(
                    hex(self.ramdump.kimage_voffset).replace('L',''))
            crashargs.append("--machdep {0}".format(kimagevoff))

        crashargs.append(os.path.abspath(self.ramdump.vmlinux))

        dumps = []
        for ram in self.ramdump.ebi_files:
            ebi_path = os.path.abspath(ram[3])
            dumps.append('{0}@0x{1:x}'.format(ebi_path, ram[1]))

        crashargs.append(",".join(dumps))

        with self.ramdump.open_file("launch_crash.sh") as f:
            f.write("#!/bin/sh\n\n")
            f.write(" ".join(crashargs))
            f.write("\n")
            os.chmod(f.name, stat.S_IRWXU)
            print_out_str("Run Crash Utility by exec: '{0}'".format(f.name))
