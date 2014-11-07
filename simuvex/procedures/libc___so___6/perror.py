import simuvex

######################################
# perror
######################################

class perror(simuvex.SimProcedure):
    def analyze(self):
        write = simuvex.SimProcedures['syscalls']['write']
        strlen = simuvex.SimProcedures['libc.so.6']['strlen']

        string = self.arg(0)
        length = self.inline_call(strlen, string).ret_expr
        self.inline_call(write, 2, string, length)

        # TODO: return values
        self.ret()
