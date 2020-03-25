"""Disassembler for GB.

This disassembler is inspired by Ghidra's SLEIGH language.
"""

from collections import OrderedDict
import enum


class DisassemblerBaseError(Exception):
    """Base disassembler error type."""


class ShortTokenInputError(DisassemblerBaseError):
    """Input buffer is short."""


class RuleError(DisassemblerBaseError):
    """The rule doesn't apply."""


class CutOffOpcodeError(DisassemblerBaseError):
    """The opcode is cut."""


class DisassemblyError(DisassemblerBaseError):
    """No disassembly for a given opcode."""


class Register(enum.IntEnum):
    """Register enumeration."""

    def __str__(self):
        return self.name

    def __repr__(self):
        return f'Register({self})'


class Token(enum.Enum):
    """An opcode field token with enum capability.

    Suited for little-endian machines.
    """

    def __init__(self, start, end, signed=False):
        """

        Args:
            start (int): The first first bit of the range.
            end (int): The last bit of the range.
            signed (bool): Whether the token should be interpreted as signed.
        """

        self._start = start
        self._end = end
        self._signed = signed

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
        return self.name

    def __repr__(self):
        signed_string = ', signed' if self.signed else ''
        return f'{self}({self.start}, {self.end}{signed_string})'

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

    ATTACHMENTS = dict()

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
            GBRegister: The register.
        """

        return type(self).ATTACHMENTS[self.token][value]


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

    def __init__(self, cookbook):
        self._cookbook = cookbook

    @property
    def cookbook(self):
        return list(self._cookbook)

    def disassemble_one(self, buffer):
        """Disassembles one instruction out of the buffer.

        Args:
            buffer (bytes): Input buffer.

        Returns:
            Instruction: Disassembled instruction.

        Raises:
            DisassemblyError: When there is no fitting recipe for the opcode.
        """

        try:
            correct_recipe = next(recipe for recipe in self.cookbook if recipe.test(buffer))
        except StopIteration:
            raise DisassemblyError(
                f'No recipe fits the opcode given in the buffer \'{buffer.hex()}\'.')
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
            else:
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

        for offset, instruction in self._whole_buffer_disassembly(buffer, address_offset):
            if instruction:
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
