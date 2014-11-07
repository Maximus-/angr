import simuvex

######################################
# __libc_start_main
######################################
class __libc_start_main(simuvex.SimProcedure):
    ADDS_EXITS = True

    def analyze(self):
        # TODO: handle symbolic and static modes
        # TODO: add argument types

        if self.state.arch.name == "PPC32":
            # for some dumb reason, PPC32 passes arguments to libc_start_main in some completely absurd way
            main_addr = self.state.mem_expr(self.state.reg_expr(48) + 4, 4, endness=self.state.arch.memory_endness)
        elif self.state.arch.name == "PPC64":
            main_addr = self.state.mem_expr(self.state.reg_expr(80) + 8, 8, endness=self.state.arch.memory_endness)
            if self.state.abiv == 'ppc64_1':
                main_addr = self.state.mem_expr(main_addr, 8, endness=self.state.arch.memory_endness)
        else:
            # Get main pc from arguments
            main_addr = self.arg(0)

        # set argc and argv
        argc = self.arg(1)
        argv = self.arg(2)
        self.set_args((argc, argv))

        # Create the new state as well
        # TODO: This is incomplete and is something just works
        # for example. it doesn't support argc and argc correctly
        new_state=self.state.copy()
        # Pushes 24 words and the retn address
        word_len = self.state.arch.bits
        # Read the existing retn address
        retn_addr_expr = self.state.stack_read(0, word_len / 8, bp=False)
        for _ in range(0, 24):
            new_state.stack_push(self.state.BVV(0, word_len))

        if self.state.arch.name in ("AMD64", "X86"):
            new_state.stack_push(retn_addr_expr)

        if self.state.arch.name == "MIPS32":
            new_state.store_reg('t9', main_addr)

        self.add_exits(simuvex.s_exit.SimExit(expr=main_addr, state=new_state, jumpkind='Ijk_Call'))
