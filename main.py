import io
import dataclasses
import struct
import typing
from wasm import *

MAGIC_NUMBER = b"\x00asm"
VERSION_1 = b"\x01\x00\x00\x00"
FUNC_TYPE = b"\x60"


@dataclasses.dataclass
class ValType:
    value: int

    def __repr__(self) -> str:
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

    def __post_init__(self) -> None:
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
    imports: list[Import] = dataclasses.field(default_factory=list)
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

    def parse_valtype(self) -> ValType:
        byte = self._read_leb128(signed=True, max=1)
        return ValType(byte)

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

    T = typing.TypeVar("T")

    def read_vec(self, reader: typing.Callable[[], T]) -> list[T]:
        count = self.read_u32()
        return [reader() for _ in range(count)]

    def parse_func_type(self) -> FuncType:
        self.expect(FUNC_TYPE)
        inputs = self.read_vec(self.parse_valtype)
        outputs = self.read_vec(self.parse_valtype)
        return FuncType(inputs, outputs)

    def parse_type_section(self, size: int) -> None:
        func_types = self.read_vec(self.parse_func_type)
        self.func_types.extend(func_types)

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

    def parse_import(self) -> Import:
        mod = self.read_name()
        name = self.read_name()
        desc_type = self.parse_importdesc()
        return Import(mod, name, desc_type)

    def parse_import_section(self, size: int) -> None:
        imports = self.read_vec(self.parse_import)
        self.imports.extend(imports)

    def parse_function_section(self, size: int) -> None:
        indices = self.read_vec(self.read_u32)
        self.functions.extend(TypeIdx(idx) for idx in indices)

    def parse_code(self) -> Code:
        size = self.read_u32()
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
        codes = self.read_vec(self.parse_code)
        self.code.extend(codes)


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


@dataclasses.dataclass(kw_only=True)
class ControlEntry:
    opcode: int
    opcode_start: int
    outputs: list[ValType]
    value_stack_top: int
    first_ref: int = -1


@dataclasses.dataclass
class SideTable:
    table: list[int] = dataclasses.field(default_factory=list)
    start_pos: int = 0

    def reset(self) -> None:
        self.table.clear()
        self.start_pos = 0

    def ref0(self, target: ControlEntry, pos: int) -> None:
        self.refV(target, pos, 0, 0)

    def refV(self, target: ControlEntry, pos: int, value_count: int, pop_count: int) -> None:
        pc = self.rel(pos)
        stp = len(self.table)
        self.putBrEntry(pc, value_count, pop_count, target.first_ref)
        target.first_ref = stp

    def refElse(self, target: ControlEntry, pos: int) -> None:
        pc = self.rel(pos)
        stp = len(self.table)
        target.else_ref = stp
        self.putBrEntry(pc, 0, 0, -1)

    def bindElse(self, target: ControlEntry, pos: int) -> None:
        self.bind0(target, target.else_ref, pos, len(self.table))
        target.else_ref = -1

    def bind0(self, *args) -> None:
        # TODO(max): Implement this
        pass

    def rel(self, pos: int) -> int:
        return pos - self.start_pos

    def putBrEntry(self, delta_pc: int, value_count: int, pop_count: int, delta_stp: int) -> None:
        self.table += [delta_pc, value_count, pop_count, delta_stp]


@dataclasses.dataclass
class Validator:
    module_env: object = dataclasses.field(default=None)

    def validate(self, parser: Parser) -> None:
        for idx, function in enumerate(parser.functions):
            func_type = parser.func_types[function.value]
            code = parser.code[idx]
            self.validate_code(parser, func_type, code)

    def validate_code(self, parser: Parser, func_type: FuncType, code: Code) -> None:
        locals: list[ValType] = func_type.inputs + code.locals
        control_stack: list[ControlEntry] = []
        value_stack: list[ValType] = []
        sidetable = SideTable()
        ip = 0
        print(f"Validating function with type {func_type} and code {code}")

        def byte() -> int:
            nonlocal ip
            ip += 1
            return code.body[ip - 1]

        def _leb128(signed: bool = False, max: int | None = None) -> int:
            """Internal LEB128 decoding routine"""
            decoded = 0
            shift = 0
            size = 1
            while True:
                byte_ = byte()
                decoded |= (byte_ & 0x7F) << shift
                shift += 7
                if byte_ & 0x80 == 0:
                    break
                if max == size:  # this also works if max=None
                    raise ValueError(
                        "encoded value seems to be >{0:d} bytes".format(size)
                    )
                size += 1
            else:
                raise ValueError("truncated value after {0:d} bytes".format(size))
            if signed and byte_ & 0x40:
                decoded -= 1 << shift

            return decoded

        def i8() -> int:
            return _leb128(signed=True, max=1)

        def u32() -> int:
            return _leb128(signed=False, max=4)

        def i32() -> int:
            return _leb128(signed=True, max=4)

        def pop(expected: ValType) -> None:
            actual = value_stack.pop()
            if actual != expected:
                raise ValueError(f"Expected {expected}; got {actual}")

        def push_multiple(types: list[ValType]) -> None:
            value_stack.extend(types)

        def check_stack_matches(expecteds: list[ValType]) -> None:
            if len(value_stack) < len(expecteds):
                raise ValueError("Stack too small")
            for i, expected in enumerate(expecteds):
                actual = value_stack[-1 - i]
                if actual != expected:
                    raise ValueError(f"Expected {expected}; got {actual}")

        def sig(inputs, outputs):
            for param in inputs:
                pop(param)
            for output in outputs:
                value_stack.append(output)

        def blocktype() -> int:
            return i8()

        def block_outputs(bt: int) -> list[ValType]:
            if bt == TYPE_VOID: return []
            if bt in (
                TYPE_I32,
                TYPE_I64,
                TYPE_F32,
                TYPE_F64,
                TYPE_V128,
                TYPE_FUNCREF,
                TYPE_EXTERNREF,
                TYPE_ANYREF,
                    ):
                return [ValType(bt)]
            raise ValueError(f"Unknown blocktype {bt}")

        while ip < len(code.body):
            opcode_start = ip
            opcode = byte()
            if opcode == INSTR_UNREACHABLE:
                pass
            elif opcode == INSTR_NOP:
                pass
            elif opcode == INSTR_GET_LOCAL:
                # TODO(max): Check that local has been initialized
                idx = u32()
                sig([], [locals[idx]])
            elif opcode == INSTR_I32_EQZ:
                sig([ValType(TYPE_I32)], [ValType(TYPE_I32)])
            elif opcode == INSTR_IF:
                bt = blocktype()
                outputs = block_outputs(bt)
                pop(ValType(TYPE_I32))  # condition
                ctl = ControlEntry(
                    opcode=opcode,
                    opcode_start=opcode_start,
                    outputs=outputs,
                    value_stack_top=len(value_stack),
                    # TODO(max): else_ref?
                )
                control_stack.append(ctl)
                sidetable.refElse(ctl, opcode_start)
            elif opcode == INSTR_ELSE:
                if not control_stack or control_stack[-1].opcode != INSTR_IF:
                    raise ValueError("Else without matching if")
                ctl = control_stack[-1]
                stack_size_since_ctl = len(value_stack) - ctl.value_stack_top
                if stack_size_since_ctl != len(ctl.outputs):
                    raise ValueError("Else with mismatched stack")
                check_stack_matches(ctl.outputs)
                # TODO(max): Reset initialization state
                sidetable.ref0(ctl, opcode_start)
                sidetable.bindElse(ctl, opcode_start+1)
                ctl.opcode = opcode
                # TODO(max): Reset stack top
                push_multiple(ctl.outputs)
            elif opcode == INSTR_I32_CONST:
                _ = i32()
                sig([], [ValType(TYPE_I32)])
            elif opcode in (INSTR_I32_SUB, INSTR_I32_ADD):
                sig([ValType(TYPE_I32), ValType(TYPE_I32)], [ValType(TYPE_I32)])
            elif opcode == INSTR_CALL:
                idx = u32()
                func_type = parser.func_types[parser.functions[idx].value]
                sig(func_type.inputs, func_type.outputs)
            elif opcode == INSTR_END:
                if control_stack:
                    control_stack.pop()
                else:
                    # End of code
                    break
            else:
                raise ValueError(
                    f"Unknown opcode {opcode} ({hex(opcode)}; {INSTR_REPR[opcode]})"
                )


with open("fib.wasm", "rb") as f:
    contents = f.read()

parser = Parser(io.BytesIO(contents))
parser.parse_module()
validator = Validator()
validator.validate(parser)
