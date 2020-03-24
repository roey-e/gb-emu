"""Disassembler for GB.

This disassembler is inspired by Ghidra's SLEIGH language.
"""

from collections import OrderedDict
import enum


class DisassemblerError(Exception):
    """Base disassembler error type."""

    pass


class ShortTokenInputError(DisassemblerError):
    """Input buffer is short."""

    pass


class RuleError(DisassemblerError):
    """The rule doesn't apply."""

    pass


class CutOffOpcodeError(DisassemblerError):
    """The opcode is cut."""

    pass


class Register(enum.IntEnum):
    """Register enumeration."""

    A = 0
    F = 1
    B = 2
    C = 3
    D = 4
    E = 5
    H = 6
    L = 7
    AF = 8
    BC = 9
    DE = 10
    HL = 11
    SP = 12
    PC = 13

    def __str__(self):
        return self.name


class Token:
    """An opcode field token."""

    def __init__(self, name, start, end, signed=False):
        """

        Args:
            start (int): The first first bit of the range.
            end (int): The last bit of the range.
            signed (bool): Whether the token should be interpreted as signed.
        """

        self._name = name
        self._start = start
        self._end = end
        self._signed = signed

    @property
    def name(self):
        """str: Token's name."""

        return self._name

    @property
    def start(self):
        """int: The first bit of the token."""

        return self._start

    @property
    def end(self):
        """int: The last bit of the token."""

        return self._end

    @property
    def signed(self):
        """bool: True for signed, False for unsigned."""

        return self._signed

    def __str__(self):
        return f'{self.name}{(self.start, self.end)}'

    def _read_buffer(self, buffer):
        """Reads the buffer in little-endian manner.

        Args:
            buffer (bytes):  An input buffer.

        Returns:
            int: The unsigned integer representing the buffer.
        """

        bytes_number = self.end // 8 + 1

        if len(buffer) < bytes_number:
            raise ShortTokenInputError(
                f'Got {len(buffer)} byte sized buffer, '
                f'{bytes_number} bytes buffer is required for extracting {self} token.')

        value = 0
        for index, byte in enumerate(buffer[:bytes_number]):
            value |= byte << (index * 8)

        return value

    def extract(self, buffer):
        """Extracts the token value out of a given buffer.

        Args:
            buffer (bytes): An input buffer.

        Returns:
            int: The parsed value.
        """

        mask = (2 ** (self.end + 1)) - 1
        value = (self._read_buffer(buffer) & mask) >> self.start

        if self.signed:
            bits = self.end - self.start + 1
            if value & (0b1 << (bits - 1)):
                value -= (0b1 << bits)

        return value


TOKENS = {
    'op0_8': Token('op0_8', 0, 7),
    'op6_2': Token('op6_2', 6, 7),
    'dRegPair4_2': Token('dRegPair4_2', 4, 5),
    'sRegPair4_2': Token('sRegPair4_2', 4, 5),
    'qRegPair4_2': Token('qRegPair4_2', 4, 5),
    'reg3_3': Token('reg3_3', 3, 5),
    'bits3_3': Token('bits3_3', 3, 5),
    'bits0_4': Token('bits0_4', 0, 3),
    'reg0_3': Token('reg0_3', 0, 2),
    'bits0_3': Token('bits0_3', 0, 2),
    'imm8': Token('imm8', 0, 7),
    'sign8': Token('sign8', 7, 7),
    'simm8': Token('simm8', 0, 7, signed=True),
    'imm16': Token('imm16', 0, 15),
}


class Rule:
    """Instruction rule."""

    def __init__(self, token, arg_name=None):
        """

        Args:
            token (Token): The token the rule is about.
            arg_name (str): The argument name to export to.
        """

        self._token = token
        self._arg_name = arg_name

    @property
    def token(self):
        """Token: The token the rule is about."""

        return self._token

    @property
    def arg_name(self):
        """str: The argument name to export to."""

        return self._arg_name if self._arg_name else self.token.name

    def __str__(self):
        raise NotImplementedError

    def _test(self, value):
        """Test for token's extracted value.

        Args:
            value (int): The extracted value.

        Returns:
            bool: True If the extracted token passes the test.
        """

        raise NotImplementedError

    def _transform(self, value):
        """The extracted token transformation.

        Args:
            value (int): The extracted value.

        Returns:
            int: The transformed value.
        """

        return value

    def test(self, buffer):
        """Tests the input by extracting the token and applying the test function.

        Args:
            buffer (bytes): An input buffer.

        Returns:
            bool: True if passes, False otherwise.
        """

        value = self.token.extract(buffer)
        return self._test(value)

    def apply(self, buffer):
        """Applies the rule on a given buffer.

        Args:
            buffer (bytes): An input buffer.

        Returns:
            (str, int): An argument-value pair.

        Raises:
            RuleError: When the rule doesn't apply.
        """

        if not self.test(buffer):
            raise RuleError(f'The rule {self} doesn\'t apply on \'{buffer.hex()}\'.')
        return self.arg_name, self._transform(self.token.extract(buffer))


class Match(Rule):
    """Instruction match rule."""

    def __init__(self, token, matched_value):
        """

        Args:
            token (Token): The token the rule is about.
            matched_value (int): The value to match the token.
        """

        self._matched_value = matched_value

        super().__init__(token)

    @property
    def matched_value(self):
        """int: The value to match the token."""

        return self._matched_value

    def __str__(self):
        return f'"{self.token} is {self.matched_value}"'

    def _test(self, value):
        return value == self.matched_value


class Attachment(Rule):
    """Instruction attachment rule."""

    ATTACHMENTS = {
        'reg0_3': {0: Register.B, 1: Register.C, 2: Register.D, 3: Register.E, 4: Register.H,
                   5: Register.L, 7: Register.A},
        'reg3_3': {0: Register.B, 1: Register.C, 2: Register.D, 3: Register.E, 4: Register.H,
                   5: Register.L, 7: Register.A},
        'sRegPair4_2': {0: Register.BC, 1: Register.DE, 2: Register.HL, 3: Register.SP},
        'dRegPair4_2': {0: Register.BC, 1: Register.DE, 2: Register.HL, 3: Register.SP},
        'qRegPair4_2': {0: Register.BC, 1: Register.DE, 2: Register.HL, 3: Register.AF},
    }

    def __init__(self, token, arg_name):
        """

        Args:
            token (Token): The token the rule is about.
            arg_name (str): The argument name to export to.
        """

        super().__init__(token, arg_name)

    def __str__(self):
        return f'"{self.token} register attachment"'

    def _test(self, value):
        try:
            return bool(self._transform(value))
        except KeyError:
            return False

    def _transform(self, value):
        """Token transformation into register.

        Args:
            value (int): The extracted value.

        Returns:
            Register: The register.
        """

        return type(self).ATTACHMENTS[self.token.name][value]


class Immediate(Rule):
    """Immediate extraction rule."""

    def __str__(self):
        return f'"{self.token} immediate extraction"'

    def _test(self, value):
        return True


class Instruction:
    """Instruction"""

    def __init__(self, format_string, args, size, duration):
        """

        Args:
            format_string (str): Instruction format string.
            args (dict): Argument dict.
            size (int): The instruction size in bytes.
            duration (int): The instruction duration in cycles.
        """

        self._format = format_string
        self._args = args
        self._size = size
        self._duration = duration

    @property
    def args(self):
        """dict: Instruction's arguments."""

        return self._args

    @property
    def size(self):
        """int: The instruction size in bytes."""

        return self._size

    @property
    def duration(self):
        """int: The instruction duration in cycles."""

        return self._duration

    def __str__(self):
        # format() doesn't use __str__ of Register.
        args = {k: str(v) for k, v in self.args.items()}
        return self._format.format(**args)

    def __repr__(self):
        return f'Instruction("{str(self)}")'


class ByteRecipe:
    """Opcode's byte rules."""

    def __init__(self, rules):
        """

        Args:
            rules (list[Rule]): List of rules.
        """

        self._rules = rules

    @property
    def rules(self):
        """list[Rule]: Rules list."""

        return list(self._rules)

    def test(self, buffer):
        """Tests the buffer against the rules.

        Args:
            buffer (bytes): Input buffer.

        Returns:
            bool: True if all the rules pass, False otherwise.
        """

        return all(rule.test(buffer) for rule in self.rules)

    def parse(self, buffer):
        """Applies the rules on the buffer to produce arguments.

        Args:
            buffer (bytes): Input buffer.

        Returns:
            dict: A dictionary that maps argument names (str) to values (int).

        Raises:
            RuleError: When one of the Rules doesn't apply.
        """

        return dict(rule.apply(buffer) for rule in self.rules)


class Recipe:
    """Instruction Recipe."""

    def __init__(self, format_string, duration, rules, *args):
        """

        Args:
            format_string (str): Instruction format string.
            duration (int): The instruction duration in cycles.
            rules (list[Rule]): List of rules.
            *args: Rules for additional bytes.
        """

        self._format = format_string
        self._duration = duration
        self._byte_recipes = [ByteRecipe(rules_list) for rules_list in [rules] + list(args)]

    @property
    def format(self):
        """str: Mnemonic format."""

        return self._format

    @property
    def duration(self):
        """int: The instruction duration in cycles."""

        return self._duration

    @property
    def byte_recipes(self):
        """list[ByteRecipe]: list of byte recipes."""

        return list(self._byte_recipes)

    @property
    def size(self):
        """int: Opcode size in bytes."""

        return len(self.byte_recipes)

    def __str__(self):
        return f'Recipe("{self.format}")'

    def test(self, buffer):
        """Tests the buffer against the byte recipes.

        Args:
            buffer (bytes): Input buffer.

        Returns:
            bool: True if all the byte recipes pass, False otherwise.

        Raises:
            CutOffOpcodeError: When the buffer is smaller than expected and passes successfully
                some of the byte recipes' tests.
        """

        if len(buffer) < 1:
            raise ValueError('Empty buffer')

        tests = [byte_recipe.test(buffer[byte:self.size]) for byte, byte_recipe in
                 enumerate(self.byte_recipes) if byte < len(buffer)]

        if len(buffer) < self.size and any(tests):
            raise CutOffOpcodeError(f'The opcode \'{buffer.hex()}\' is cut as tested by {self}.')

        return all(tests)

    def parse(self, buffer):
        """Parses the buffer to produce an instruction.

        Args:
            buffer (bytes): Input buffer.

        Returns:
            Instruction: Resulted instruction.

        Raises:
            RuleError: When one of the Rules doesn't apply.
            CutOffOpcodeError: When the buffer is smaller than expected and parses successfully
                by some of the byte recipes.
        """

        if len(buffer) < 1:
            raise ValueError('Empty buffer')

        args = dict()
        for byte, byte_recipe in enumerate(self.byte_recipes):
            if byte < len(buffer):
                args.update(byte_recipe.parse(buffer[byte:self.size]))

        if len(buffer) < self.size and args:
            raise CutOffOpcodeError(f'The opcode \'{buffer.hex()}\' is cut as tested by {self}.')

        return Instruction(self.format, args, self.size, self.duration)


class Disassembler:
    """GB Disassembler."""

    COOKBOOK = [
        Recipe('LD {dst},{src}', 4, [Match(TOKENS['op6_2'], 0x1),
                                     Attachment(TOKENS['reg3_3'], 'dst'),
                                     Attachment(TOKENS['reg0_3'], 'src')]),
        Recipe('LD {dst},{imm}', 8, [Match(TOKENS['op6_2'], 0x0),
                                     Attachment(TOKENS['reg3_3'], 'dst'),
                                     Match(TOKENS['bits0_3'], 0x6)],
               [Immediate(TOKENS['imm8'], 'imm')])
    ]

    def disassemble_one(self, buffer):
        """Disassembles one instruction out of the buffer.

        Args:
            buffer (bytes): Input buffer.

        Returns:
            Instruction: Disassembled instruction.
        """

        correct_recipe = next(recipe for recipe in type(self).COOKBOOK if recipe.test(buffer))
        return correct_recipe.parse(buffer)

    def _whole_buffer_disassembly(self, buffer, address_offset=0):
        """Disassembly generator that goes all over the buffer including a possible cut opcode.

        Args:
            buffer (bytes): Input buffer.
            address_offset (int): The relative offset of the given buffer.

        Yields:
            (int, Instruction): An offset and the disassembled instruction.
        """

        offset = address_offset
        while buffer:
            try:
                instruction = self.disassemble_one(buffer)
            except CutOffOpcodeError:
                yield offset, None
                return
            yield offset, instruction
            buffer = buffer[instruction.size:]
            offset += instruction.size

    def disassembly(self, buffer, address_offset=0):
        """Disassembly generator that goes over the buffer.

        Args:
            buffer (bytes): Input buffer.
            address_offset (int): The relative offset of the given buffer.

        Yields:
            (int, Instruction): An offset and the disassembled instruction.
        """

        whole_buffer_disassembly = self._whole_buffer_disassembly(buffer, address_offset)
        while True:
            try:
                offset, instruction = next(whole_buffer_disassembly)
            except StopIteration:
                return
            else:
                if not instruction:
                    return
            yield offset, instruction

    def disassemble(self, buffer, address_offset=0):
        """Disassembles a buffer.

        Args:
            buffer (bytes): Input buffer.
            address_offset (int): The relative offset of the given buffer.

        Returns:
            OrderedDict: An ordered dict that maps addresses to instructions.
        """

        return OrderedDict(self._whole_buffer_disassembly(buffer, address_offset))


if __name__ == '__main__':
    ld_recipe = Recipe('LD {dst},{src}', 4, [Match(TOKENS['op6_2'], 0x1),
                                             Attachment(TOKENS['reg3_3'], 'dst'),
                                             Attachment(TOKENS['reg0_3'], 'src')])
    print(ld_recipe.test(b'\x40'))
    print(ld_recipe.test(b'\x78'))
    print(ld_recipe.test(b'\x46'))
    print(ld_recipe.test(b'\x06'))
    print(ld_recipe.parse(b'\x53'))

    two_byte_ld_recipe = Recipe('LD {dst},{imm}', 8, [Match(TOKENS['op6_2'], 0x0),
                                                      Attachment(TOKENS['reg3_3'], 'dst'),
                                                      Match(TOKENS['bits0_3'], 0x6)],
                                [Immediate(TOKENS['imm8'], 'imm')])
    instruction = two_byte_ld_recipe.parse(b'\x06\x45')
    print(f'{instruction}, size:{instruction.size} bytes, duration: {instruction.duration} cycles')
    try:
        print(two_byte_ld_recipe.parse(b'\x06'))
    except CutOffOpcodeError as e:
        print(e)

    dis = Disassembler()

    print(dis.disassemble_one(b'\x53'))
    print(dis.disassemble_one(b'\x06\x45'))
    print(list(dis.disassembly(b'\x06\x45\x53')))
    print(dis.disassemble(b'\x06\x45\x53', 10))
    print(list(dis.disassembly(b'\x06\x45\x53\x06')))
    print(dis.disassemble(b'\x06\x45\x53\x06', 10))
