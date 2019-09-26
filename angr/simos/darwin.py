import logging

from .userland import SimUserland

import claripy
from ..tablespecs import StringTableSpec
from ..procedures import SIM_PROCEDURES as P, SIM_LIBRARIES as L

l = logging.getLogger(name='simos.darwin')

class SimDarwin(SimUserland):
    def __init__(self, project, **kwargs):
        l.warning('AAAAAAAAAAAAAAAAAAAAA')
        super(SimDarwin, self).__init__(project, 
                syscall_library=L['darwin'],
                syscall_addr_alignment=project.arch.instruction_alignment, 
                name='darwin')

    def configure_project(self):
        super(SimDarwin, self).configure_project(['amd64'])

        # Setup dyld loader stub here..
    def state_entry(self, args=None, env=None, argc=None, **kwargs):
        l.warning('setting up state entry..')

        state = super(SimDarwin, self).state_entry(**kwargs)

        sp = state.regs.sp

        for reg in state.arch.default_symbolic_registers:
            state.registers.store(reg, 0)

        state.regs.sp = sp

        # Handle default values
        filename = self.project.filename or 'dummy_filename'
        if args is None:
            args = [filename]

        if env is None:
            env = {}

        # Prepare argc
        if argc is None:
            argc = claripy.BVV(len(args), state.arch.bits)
        elif type(argc) is int:  # pylint: disable=unidiomatic-typecheck
            argc = claripy.BVV(argc, state.arch.bits)

        # "dyld_file=0x1901000005,0x203623ce2"
        # "main_stack=0x7ffeefc00000,0x800000,0x7ffeebc00000,0x4000000"
        # "malloc_entropy=0x7e77f07b1decedd1,0xf50c2e72b8885a96"
        # "pfz=0x7ffffffe9000"
        # "executable_file=0x1901000005,0x203b685fc"
        # "ptr_munge=0xf6eae75a63904973"
        # "stack_guard=0xe177fe0376990045"
        # "executable_path=/Users/max/angr_dev/lib/python3.7/site-packages/pyvex/lib/test2"

        # Make string table for args/env/apple
        table = StringTableSpec()

        # Add args to string table
        table.append_args(args)

        # Add environment to string table
        table.append_env(env)

        table.add_null()
        table.add_null()

        # Dump the table onto the stack, calculate pointers to args, env, and auxv
        state.memory.store(state.regs.sp - 16, claripy.BVV(0, 8 * 16))
        argv = table.dump(state, state.regs.sp - 16)
        envp = argv + ((len(args) + 1) * state.arch.bytes)
        auxv = argv + ((len(args) + len(env) + 2) * state.arch.bytes)

        # Put argc on stack and fix the stack pointer
        newsp = argv - state.arch.bytes
        state.memory.store(newsp, argc, endness=state.arch.memory_endness)
        state.regs.sp = newsp

        # store argc argv envp auxv in the posix plugin
        state.posix.argv = argv
        state.posix.argc = argc
        state.posix.environ = envp
        state.posix.auxv = auxv
        self.set_entry_register_values(state)

        # Get this symbol from self.project.loader.all_images['dyld'].symbol('__dyld_start')
        state.regs.rip = 0x201001000

        return state

    def state_blank(self, fs=None, concrete_fs=False, chroot=None, cwd=b'/Users/user', pathsep='/', **kwargs): 
        state = super(SimDarwin, self).state_blank(**kwargs)
        l.warning('Setting up blank state..')
        return state

    def set_entry_register_values(self, state):
        for reg, val in state.arch.entry_register_values.items():
            if isinstance(val, int):
                state.registers.store(reg, val)
            elif isinstance(val, (str,)):
                if val == 'argc':
                    state.registers.store(reg, state.posix.argc, size=state.arch.bytes)
                elif val == 'argv':
                    state.registers.store(reg, state.posix.argv)
                elif val == 'envp':
                    state.registers.store(reg, state.posix.environ)
                elif val == 'apple':
                    state.registers.store(reg, state.posix.auxv)
                elif val == 'ld_destructor':
                    # a pointer to the dynamic linker's destructor routine, to be called at exit
                    # or NULL. We like NULL. It makes things easier.
                    state.registers.store(reg, 0)
                elif val == 'toc':
                    if self.project.loader.main_object.is_ppc64_abiv1:
                        state.registers.store(reg, self.project.loader.main_object.ppc64_initial_rtoc)
                elif val == 'thread_pointer':
                    state.registers.store(reg, self.project.loader.tls_object.user_thread_pointer)
                else:
                    _l.warning('Unknown entry point register value indicator "%s"', val)
            else:
                _l.error('What the ass kind of default value is %s?', val)
