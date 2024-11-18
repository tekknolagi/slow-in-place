import io
import dataclasses
import struct
from wasm import *

MAGIC_NUMBER = b"\x00asm"
VERSION_1 = b"\x01\x00\x00\x00"
FUNC_TYPE = b"\x60"


@dataclasses.dataclass
class ValType:
    value: int

    def __repr__(self):
        return TYPE_REPR[self.value]


IMPORT_DESC_FUNC = 0x00
IMPORT_DESC_TABLE = 0x01
IMPORT_DESC_MEMORY = 0x02
IMPORT_DESC_GLOBAL = 0x03


@dataclasses.dataclass
class FuncType:
    inputs: list[ValType]
    outputs: list[ValType]


@dataclasses.dataclass
class Limits:
    min: int
    max: int | None


@dataclasses.dataclass
class TableType:
    elem_type: ValType
    limits: Limits

    def __post_init__(self):
        if self.elem_type.value not in (TYPE_FUNCREF, TYPE_EXTERNREF):
            raise ValueError(f"Invalid elem_type {self.elem_type}")


@dataclasses.dataclass
class MemoryType:
    limits: Limits


@dataclasses.dataclass
class GlobalType:
    val_type: ValType
    mutable: bool


@dataclasses.dataclass
class ImportDesc:
    pass


@dataclasses.dataclass
class FuncImportDesc(ImportDesc):
    type_idx: int


@dataclasses.dataclass
class TableImportDesc(ImportDesc):
    table_type: TableType


@dataclasses.dataclass
class MemoryImportDesc(ImportDesc):
    memory_type: MemoryType


@dataclasses.dataclass
class GlobalImportDesc(ImportDesc):
    global_type: GlobalType


@dataclasses.dataclass
class Import:
    module: str
    name: str
    desc: ImportDesc


@dataclasses.dataclass
class TypeIdx:
    value: int


@dataclasses.dataclass
class Code:
    locals: list[ValType]
    body: bytes


@dataclasses.dataclass
class Parser:
    module: io.BytesIO
    func_types: list[FuncType] = dataclasses.field(default_factory=list)
    imports: list[ImportDesc] = dataclasses.field(default_factory=list)
    functions: list[TypeIdx] = dataclasses.field(default_factory=list)
    code: list[Code] = dataclasses.field(default_factory=list)

    def expect(self, expected: bytes) -> None:
        actual = self.module.read(len(expected))
        if len(actual) < len(expected):
            raise ValueError(f"Unexpected EOF; expected {expected!r}")
        if actual != expected:
            raise ValueError(f"Expected {expected!r}; got {actual!r}")

    def _read_leb128(self, signed: bool = False, max: int | None = None) -> int:
        """Internal LEB128 decoding routine"""
        decoded = 0
        shift = 0

        size = 1
        while True:
            byte_ = self.module.read(1)
            if not byte_:
                raise ValueError("unexpected EOF")
            byte = byte_[0]
            decoded |= (byte & 0x7F) << shift
            shift += 7
            if byte & 0x80 == 0:
                break

            if max == size:  # this also works if max=None
                raise ValueError("encoded value seems to be >{0:d} bytes".format(size))
            size += 1

        else:
            # Reached when no 'break' was issued in the loop above.
            raise ValueError("truncated value after {0:d} bytes".format(size))

        # Negative numbers have a sign bit in the last byte.
        if signed and byte & 0x40:
            decoded -= 1 << shift

        return decoded

    def read_byte(self) -> int:
        byte_ = self.module.read(1)
        if not byte_:
            raise ValueError("unexpected EOF")
        return byte_[0]

    def read_u32(self) -> int:
        return self._read_leb128(signed=False, max=4)

    def read_s7(self) -> int:
        return self._read_leb128(signed=True, max=1)

    def parse_valtype(self) -> ValType:
        return ValType(self.read_s7())

    def read_name(self) -> str:
        size = self.read_u32()
        return self.module.read(size).decode("utf-8")

    def parse_module(self) -> None:
        self.expect(MAGIC_NUMBER)
        self.expect(VERSION_1)
        while True:
            sec_type_ = self.module.read(1)
            if not sec_type_:
                break
            sec_type = sec_type_[0]
            sec_size = self.read_u32()
            before = self.module.tell()
            if sec_type == SEC_TYPE:
                self.parse_type_section(sec_size)
            elif sec_type == SEC_IMPORT:
                self.parse_import_section(sec_size)
            elif sec_type == SEC_FUNCTION:
                self.parse_function_section(sec_size)
            elif sec_type == SEC_CODE:
                self.parse_code_section(sec_size)
            else:
                print(f"Skipping section {sec_type}")
                self.module.seek(sec_size, io.SEEK_CUR)
            after = self.module.tell()
            assert (
                after - before == sec_size
            ), f"Expected {sec_size} bytes, read {after - before}"

    def parse_func_type(self) -> FuncType:
        self.expect(FUNC_TYPE)
        input_count = self.read_u32()
        inputs = []
        for _ in range(input_count):
            inputs.append(self.parse_valtype())
        output_count = self.read_u32()
        outputs = []
        for _ in range(output_count):
            outputs.append(self.parse_valtype())
        return FuncType(inputs, outputs)

    def parse_type_section(self, size: int) -> None:
        count = self.read_u32()
        for idx in range(count):
            assert idx == len(self.func_types)
            self.func_types.append(self.parse_func_type())

    def parse_importdesc(self) -> ImportDesc:
        kind = self.read_byte()
        if kind == IMPORT_DESC_FUNC:
            type_idx = self.read_u32()
            return FuncImportDesc(type_idx)
        elif kind == IMPORT_DESC_TABLE:
            table_type = self.parse_tabletype()
            return TableImportDesc(table_type)
        elif kind == IMPORT_DESC_MEMORY:
            memory_type = self.parse_memorytype()
            return MemoryImportDesc(memory_type)
        elif kind == IMPORT_DESC_GLOBAL:
            global_type = self.parse_globaltype()
            return GlobalImportDesc(global_type)
        else:
            raise ValueError(f"Unknown importdesc kind {kind}")

    def parse_import_section(self, size: int) -> None:
        count = self.read_u32()
        for _ in range(count):
            mod = self.read_name()
            name = self.read_name()
            desc_type = self.parse_importdesc()
            self.imports.append(Import(mod, name, desc_type))

    def parse_function_section(self, size: int) -> None:
        count = self.read_u32()
        for _ in range(count):
            type_idx = self.read_u32()
            self.functions.append(TypeIdx(type_idx))

    def parse_code(self, size: int) -> Code:
        before = self.module.tell()
        locals = []
        local_count = self.read_u32()
        for _ in range(local_count):
            count = self.read_u32()
            valtype = self.parse_valtype()
            locals.extend([valtype] * count)
        locals_size = self.module.tell() - before
        body = self.module.read(size - locals_size)
        return Code(locals, body)

    def parse_code_section(self, size: int) -> None:
        count = self.read_u32()
        for _ in range(count):
            code_size = self.read_u32()
            before = self.module.tell()
            code = self.parse_code(code_size)
            after = self.module.tell()
            assert (
                after - before == code_size
            ), f"Expected {code_size} bytes, read {after - before}"
            self.code.append(code)


@dataclasses.dataclass
class Value:
    pass


@dataclasses.dataclass
class NumValue(Value):
    type: ValType
    value: int | float


@dataclasses.dataclass
class RefValue(Value):
    type: ValType
    value: int


@dataclasses.dataclass
class Control:
    pass


@dataclasses.dataclass
class Func(Control):
    pass


@dataclasses.dataclass
class Block(Control):
    pass


@dataclasses.dataclass
class If(Control):
    pass


@dataclasses.dataclass
class Validator:
    module_env: object = dataclasses.field(default=None)

    def validate(self, parser: Parser) -> None:
        for idx, function in enumerate(parser.functions):
            func_type = parser.func_types[function.value]
            code = parser.code[idx]
            self.validate_code(func_type, code)

    def validate_code(self, func_type: FuncType, code: Code) -> None:
        control_stack: list[Control] = []
        value_stack: list[ValType] = []
        print(f"Validating function with type {func_type} and code {code}")


with open("fib.wasm", "rb") as f:
    contents = f.read()

parser = Parser(io.BytesIO(contents))
parser.parse_module()
validator = Validator()
validator.validate(parser)
