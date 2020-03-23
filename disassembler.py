"""Disassembler for GB.

This disassembler is inspired by Ghidra's SLEIGH language.
"""

import enum


class DisassemblerError(Exception):
    """Base disassembler error type."""

    pass


class ShortInputError(DisassemblerError):
    """Input buffer is short."""

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
            raise ShortInputError(
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
        """

        if not self.test(buffer):
            raise ValueError('The rule doesn\'t apply.')
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


class Instruction:
    """Instruction"""

    def __init__(self, format_string, args):
        """

        Args:
            format_string (str): Instruction format string.
            args (dict): Argument dict.
        """

        self._format = format_string
        self._args = args

    @property
    def mnem(self):
        """str: Mnemonic."""

        return self._format.split()[0]

    @property
    def args(self):
        """dict: Instruction's arguments."""

        return self._args

    def __str__(self):
        # format() doesn't use __str__ of Register.
        args = {k: str(v) for k, v in self.args.items()}
        return self._format.format(**args)


class Recipe:
    """Instruction Recipe."""

    def __init__(self, format_string, rules):
        """

        Args:
            format_string (str): Instruction format string.
            rules (list[Rule]): List of rules.
        """

        self._format = format_string
        self._rules = rules
        self._args = {}

    @property
    def mnem(self):
        """str: Mnemonic."""

        return self._format.split()[0]

    @property
    def rules(self):
        """list[Rule]: Rules list."""

        return self._rules

    def test(self, buffer):
        """Tests the buffer against the recipe.

        Args:
            buffer (bytes): An input buffer

        Returns:
            bool: True if all the rules pass, False otherwise.
        """

        return all(rule.test(buffer) for rule in self.rules)

    def parse(self, buffer):
        """Parses the buffer to produce an instruction.

        Args:
            buffer (bytes): An input buffer

        Returns:
            Instruction: Resulted instruction.
        """

        if self.test(buffer):
            return Instruction(self._format, dict(rule.apply(buffer) for rule in self.rules))


if __name__ == '__main__':
    ld_recipe = Recipe('LD {dst},{src}', [Match(TOKENS['op6_2'], 0x1),
                                          Attachment(TOKENS['reg3_3'], 'dst'),
                                          Attachment(TOKENS['reg0_3'], 'src')])
    print(ld_recipe.test(b'\x40'))
    print(ld_recipe.test(b'\x78'))
    print(ld_recipe.test(b'\x46'))
    print(ld_recipe.test(b'\x06'))
    print(ld_recipe.parse(b'\x53'))
