#!/usr/bin/env python
from .s_procedure import SimProcedure, SimProcedureError
import string
import simuvex
import logging

l = logging.getLogger("simuvex.parseformat")

class FormatString(object):
    """
    describes a format string
    """

    def __init__(self, parser, components):
        """
        takes a list of components which are either just strings or a FormatSpecifier
        """
        self.components = components
        self.parser = parser
        self.string = None

    def _add_to_string(self, string, c):

        if c is None:
            return string
        if string is None:
            return c
        return string.concat(c)

    def _get_str_at(self, str_addr):

        strlen = self.parser._sim_strlen(str_addr)

        #TODO: we probably could do something more fine-grained here.

        # throw away strings which are just the NULL terminator
        if self.parser.state.se.max_int(strlen) == 0:
            return None
        return self.parser.state.memory.load(str_addr, strlen)

    def replace(self, startpos, args):
        """
        produce a new string based of the format string @self with args @args
        return a new string, possibly symbolic
        """

        argpos = startpos
        string = None

        for component in self.components:
            # if this is just concrete data
            if isinstance(component, str):
                string = self._add_to_string(string, self.parser.state.BVV(component))
            else:
                # okay now for the interesting stuff
                # what type of format specifier is it?
                fmt_spec = component
                if fmt_spec.spec_type == 's':
                    str_ptr = args(argpos)
                    string = self._add_to_string(string, self._get_str_at(str_ptr))
                # integers, for most of these we'll end up concretizing values..
                else:
                    i_val = args(argpos)
                    c_val = int(self.parser.state.se.any_int(i_val))
                    c_val &= (1 << (fmt_spec.size * 8)) - 1
                    if fmt_spec.signed and (c_val & (1 << ((fmt_spec.size * 8) - 1))):
                        c_val -= (1 << fmt_spec.size * 8)

                    if fmt_spec.spec_type == 'd':
                        s_val = str(c_val)
                    elif fmt_spec.spec_type == 'u':
                        s_val = str(c_val)
                    elif fmt_spec.spec_type == 'c':
                        s_val = chr(c_val & 0xff)
                    elif fmt_spec.spec_type == 'x':
                        s_val = hex(c_val)[2:].rstrip('L')
                    elif fmt_spec.spec_type == 'o':
                        s_val = oct(c_val)[1:].rstrip('L')
                    elif fmt_spec.spec_type == 'p':
                        s_val = hex(c_val).rstrip('L')
                    else:
                        raise SimProcedureError("Unimplemented format specifier '%s'" % fmt_spec.spec_type)

                    string = self._add_to_string(string, self.parser.state.BVV(s_val))

                argpos += 1

        return string

    def interpret(self, addr, startpos, args, region=None):
        '''
        interpret a format string, reading the data @addr in @region into @args starting at @startpos
        '''

        assert len(filter(lambda x: isinstance(x, FormatSpecifier), self.components)) == 1, "too many format specifiers for simprocedure"

        if region is None:
            region = self.parser.state.memory

        argpos = startpos 
        position = addr
        for component in self.components:
            if isinstance(component, str):     
                # TODO, if the region doesn't match the concrete component, we need to return immediately
                pass
            else:
                fmt_spec = component
                dest = args(argpos)
                if fmt_spec.spec_type == 's':
                    # get length of the string from region
                    ohr, ohc, ohi = region.find(position, self.parser.state.BVV('\n', 8), self.parser.state.libc.max_str_len, max_symbolic_bytes=self.parser.state.libc.buf_symbolic_bytes)
                    #nr, nc, ni = region.find(position, self.parser.state.BVV('\n', 8), self.parser.state.libc.max_str_len, max_symbolic_bytes=self.parser.state.libc.buf_symbolic_bytes)
                    #sr, sc, si = region.find(position, self.parser.state.BVV(' ', 8), self.parser.state.libc.max_str_len, max_symbolic_bytes=self.parser.state.libc.buf_symbolic_bytes)
                    mm = ohr
                    #mm = self.parser.state.se.If(sr < nr, sr, nr)
                    #mm = self.parser.state.se.If(ohr < mm, ohr, mm)

                    # we're just gonna concretize it..
                    length = self.parser.state.se.max_int(mm - position)
                    src_str = region.load(position, length)
                    # write it out to the pointer
                    self.parser.state.memory.store(dest, src_str)

                    position += length

                else:

                    #nr, nc, ni= region.find(position, self.parser.state.BVV('\n', 8), self.parser.state.libc.max_str_len, max_symbolic_bytes=self.parser.state.libc.buf_symbolic_bytes)
                    
                    i = self.parser._sim_atoi_inner(position, region)
                    position += 1
                    if fmt_spec.spec_type == 'd':
                        pass
                    elif fmt_spec.spec_type == 'u':
                        pass
                    else:
                        raise SimProcedureError("unsupported format spec '%s' in interpret" % fmt_spec.spec_type)

                    self.parser.state.memory.store(dest, i, endness='Iend_LE')

                argpos += 1 
            
        return (position, self.parser.state.BVV(argpos - startpos))

    def __repr__(self):
        outstr = ""
        for comp in self.components:
            outstr += (str(comp))

        return outstr

class FormatSpecifier(object):
    """
    describes a format specifier within a format string
    """

    def __init__(self, string, size, signed):
        self.string = string
        self.size = size
        self.signed = signed

    @property
    def spec_type(self):
        return self.string[-1].lower()

    def __str__(self):
        return "%%%s" % self.string

    def __len__(self):
        return len(self.string)

class FormatParser(SimProcedure):
    """
    For SimProcedures relying on format strings.
    """

    # Basic conversion specifiers for format strings, mapped to Simuvex s_types
    # TODO: support for C and S that are deprecated.
    # TODO: We only consider POSIX locales here.
    basic_spec = {
        'd': 'int',
        'i': 'int',
        'o': 'uint',
        'u': 'uint',
        'x': 'uint',
        'X': 'uint',
        'e': 'dword',
        'E': 'dword',
        'f': 'dword',
        'F': 'dword',
        'g': 'dword',
        'G': 'dword',
        'a': 'dword',
        'A': 'dword',
        'c': 'char',
        's': 'string',
        'p': 'uintptr_t',
        'n': 'uintptr_t', # pointer to num bytes written so far
        'm': None, # Those don't expect any argument
        '%': None, # Those don't expect any argument
    }

    # Signedness of integers
    int_sign = {
        'signed': ['d', 'i'],
        'unsigned' : ['o', 'u', 'x', 'X']
    }

    # Length modifiers and how they apply to integer conversion (signed /
    # unsinged)
    int_len_mod = {
        'hh': ('char', 'uint8_t'),
        'h' : ('int16_t', 'uint16_t'),
        'l' : ('long', ('unsigned', 'long')),
        # FIXME: long long is 64bit according to stdint.h on Linux,  but that might not always be the case
        'll' : ('int64_t', 'uint64_t'),

        # FIXME: intmax_t seems to be always 64 bit, but not too sure
        'j' : ('int64_t', 'uint64_t'),
        'z' : ('ssize', 'size_t'), # TODO: implement in s_type
        't' : ('ptrdiff_t', 'ptrdiff_t'), # TODO: implement in s_type
    }

    # Types that are not known by Simuvex.s_types
    # Maps to (size, signedness)
    other_types = {
        ('string',): lambda _:(0, True) # special value for strings, we need to count
    }

    # Those flags affect the formatting the output string
    flags = ['#', '0', r'\-', r' ', r'\+', r'\'', 'I']

    @property
    def _mod_spec(self):
        """
        Modified length specifiers: mapping between length modifiers and
        conversion specifiers.  This generates all the possibilities, i.e. hhd,
        etc.
       """
        mod_spec={}

        for mod, sizes in self.int_len_mod.iteritems():

            for conv in self.int_sign['signed']:
                mod_spec[mod + conv] = sizes[0]

            for conv in self.int_sign['unsigned']:
                mod_spec[mod + conv] = sizes[1]

        return mod_spec

    @property
    def _all_spec(self):
        """
        All specifiers and their lengths
        """

        base = self._mod_spec

        for spec in self.basic_spec:
            base[spec] = self.basic_spec[spec]

        return base

    # Tricky stuff
    # Note that $ is not C99 compliant (but posix specific).

    def _match_spec(self, nugget):
        """
        match the string @nugget to a format specifer.
        TODO: handle positional modifiers and other similar format string tricks
        """
        all_spec = self._all_spec

        # is it an actual format?
        for spec in all_spec:
            if nugget.startswith(spec):
                # this is gross coz simuvex.s_type is gross..
                nugget = nugget[:len(spec)]
                nugtype = all_spec[nugget]
                if nugtype in simuvex.s_type.ALL_TYPES:
                    typeobj = simuvex.s_type.ALL_TYPES[nugtype](self.state.arch)
                elif (nugtype,) in simuvex.s_type._C_TYPE_TO_SIMTYPE:
                    typeobj = simuvex.s_type._C_TYPE_TO_SIMTYPE[(nugtype,)](self.state.arch)
                else:
                    raise SimProcedureError("format specifier uses unknown type '%s'" % nugtype)
                return FormatSpecifier(nugget, typeobj.size / 8, typeobj.signed)

        return None

    def _get_fmt(self, fmt):
        """
        Extract the actual formats from the format string @fmt
        Returns a FormatString object
        """

        # iterate over the format string looking for format specifiers
        components = [ ]
        i = 0
        while i < len(fmt):
            if fmt[i] == "%":
                # grab the specifier
                # go to the space
                specifier = fmt[i+1:]


                # iterate through nugget throwing away anything which is an int
                # TODO store this in a size variable
                for j, c in enumerate(specifier):
                    if not (c in string.digits):
                        specifier= specifier[j:]
                        i += j
                        break

                specifier = self._match_spec(specifier)
                if specifier is not None:
                    i += len(specifier)
                    components.append(specifier)
                else:
                    # if we get here we didn't match any specs, the first char will be thrown away
                    # and we'll add the percent
                    i += 1
                    components.append('%')
            else:
                components.append(fmt[i])
            i += 1

        return FormatString(self, components)

    def _sim_atoi_inner(self, str_addr, region):
        """
        Return the result of invoking the atoi simprocedure on str_addr
        """

        atoi = simuvex.SimProcedures['libc.so.6']['atoi']
        
        return atoi._atoi_inner(str_addr, self.state, region)

    def _sim_strlen(self, str_addr):
        """
        Return the result of invoked the strlen simprocedure on std_addr
        """

        strlen = simuvex.SimProcedures['libc.so.6']['strlen']

        return self.inline_call(strlen, str_addr).ret_expr


    def _parse(self, fmt_idx):
        """
        Parse format strings.
        Returns: a FormatString object which can be used for replacing the format specifiers with
        arguments or for scanning into arguments

        @fmt_idx: index of the (pointer to the) format string in the arguments
        list.
        """

        fmtstr_ptr = self.arg(fmt_idx)

        if self.state.se.symbolic(fmtstr_ptr):
            raise SimProcedureError("Symbolic pointer to (format) string :(")

        length = self._sim_strlen(fmtstr_ptr)
        if self.state.se.symbolic(length):
            raise SimProcedureError("Symbolic (format) string, game over :(")

        fmt_xpr = self.state.memory.load(fmtstr_ptr, length)
        fmt = self.state.se.any_str(fmt_xpr)

        # make a FormatString object
        fmt_str = self._get_fmt(fmt)

        l.debug("Fmt: %r", fmt_str)

        return fmt_str
