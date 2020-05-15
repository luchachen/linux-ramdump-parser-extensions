from parser_util import register_parser, RamParser
from print_out import print_out_str

@register_parser('--bootmsg', 'Print the bootmsg')
class Bootmsg(RamParser):

    def parse(self):
        ramdump = self.ramdump
        bootmsg_buffer = ramdump.read_word(ramdump.address_of("bootmsg_buffer"))
        if not bootmsg_buffer:
            print_out_str("Cannot find bootmsg_buffer")
            return

        bootmsg_len = ramdump.read_u32(ramdump.address_of("bootmsg_len"))
        if not bootmsg_len:
            print_out_str("Cannot find bootmsg_len")
            return

        bootmsg = "".join(ramdump.read_string(bootmsg_buffer, "{}s".format(bootmsg_len)))
        self.bootmsg_file = self.ramdump.open_file("bootmsg.txt")
        self.bootmsg_file.write(bootmsg)
        self.bootmsg_file.close()
        print_out_str("Wrote to bootmsg.txt")
