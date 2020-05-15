from boards import Board, register_board

class BoardTrinket(Board):
    def __init__(self, socid):
        super(BoardTrinket, self).__init__()
        self.socid = socid
        self.board_num = "trinket"
        self.cpu = 'CORTEXA53'
        self.ram_start = 0x40000000
        self.smem_addr = 0x6000000
        self.smem_addr_buildinfo = 0x6007210
        self.phys_offset = 0x40000000
        self.imem_start = 0x0c100000
        self.kaslr_addr = 0x0c1256d0
        self.wdog_addr = 0x0c125658
        self.imem_file_name = 'OCIMEM.BIN'

class BoardLito(Board):
    def __init__(self, socid):
        super(BoardLito, self).__init__()
        self.socid = socid
        self.board_num = "lito"
        self.cpu = 'CORTEXA53'
        self.ram_start = 0x80000000
        self.smem_addr = 0x900000
        self.smem_addr_buildinfo = 0x907210
        self.phys_offset = 0xA7E00000
        self.imem_start = 0x14680000
        self.kaslr_addr = 0x146ab6d0
        self.wdog_addr = 0x146ab658
        self.imem_file_name = 'OCIMEM.BIN'

register_board(BoardTrinket(socid=394))
register_board(BoardLito(socid=400))
