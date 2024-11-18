import io
import dataclasses
import struct

MAGIC_NUMBER = b"\x00asm"
VERSION_1 = b"\x01\x00\x00\x00"
FUNC_TYPE = b"\x60"
SEC_CUSTOM = 0
SEC_TYPE = 1
SEC_IMPORT = 2
SEC_FUNCTION = 3
SEC_TABLE = 4
SEC_MEMORY = 5
SEC_GLOBAL = 6
SEC_EXPORT = 7
SEC_START = 8
SEC_ELEMENT = 9
SEC_CODE = 10
SEC_DATA = 11
SEC_DATA_COUNT = 12


@dataclasses.dataclass
class ValType:
    pass


@dataclasses.dataclass
class NumType(ValType):
    kind: str
    size_bytes: int


I32 = NumType("i", 4)
I64 = NumType("i", 8)
F32 = NumType("f", 4)
F64 = NumType("f", 8)
V128 = NumType("v", 16)


@dataclasses.dataclass
class RefType(ValType):
    kind: str


FuncRef = RefType("funcref")
ExternRef = RefType("externref")

BYTE_TO_VALTYPE = {
    0x7F: I32,
    0x7E: I64,
    0x7D: F32,
    0x7C: F64,
    0x7B: V128,
    0x70: FuncRef,
    0x6F: ExternRef,
}

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
    elem_type: RefType
    limits: Limits


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
    size: int
    locals: list[ValType]
    body: bytes


@dataclasses.dataclass
class Validator:
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
            assert after - before == sec_size, f"Expected {sec_size} bytes, read {after - before}"

    def parse_func_type(self) -> FuncType:
        self.expect(FUNC_TYPE)
        input_count = self.read_u32()
        inputs = []
        for _ in range(input_count):
            val_type = self.read_byte()
            inputs.append(BYTE_TO_VALTYPE[val_type])
        output_count = self.read_u32()
        outputs = []
        for _ in range(output_count):
            val_type = self.read_byte()
            outputs.append(BYTE_TO_VALTYPE[val_type])
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

    def parse_code(self) -> Code:
        size = self.read_u32()
        locals = []
        local_count = self.read_u32()
        for _ in range(local_count):
            count = self.read_u32()
            val_type = self.read_byte()
            locals.extend([BYTE_TO_VALTYPE[val_type]] * count)
        body = self.module.read(size)
        return Code(size, locals, body)

    def parse_code_section(self, size: int) -> None:
        count = self.read_u32()
        for _ in range(count):
            code = self.parse_code()
            self.code.append(code)


with open("simple.wasm", "rb") as f:
    contents = f.read()

validator = Validator(io.BytesIO(contents))
validator.parse_module()
