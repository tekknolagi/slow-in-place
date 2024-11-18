UNREACHABLE = 0X0
NOP = 0X1
BLOCK = 0X2
LOOP = 0X3
IF = 0X4
ELSE = 0X5
TRY = 0X6
CATCH = 0X7
THROW = 0X8
RETHROW = 0X9
THROW_REF = 0XA
BR = 0XC
BR_IF = 0XD
BR_TABLE = 0XE
RETURN = 0XF
DELEGATE = 0X18
CATCH_ALL = 0X19
DROP = 0X1A
SELECT = 0X1B
ANNOTATED_SELECT = 0X1C
TRY_TABLE = 0X1F
END = 0XB
I32_CONST = 0X41
I64_CONST = 0X42
F64_CONST = 0X44
F32_CONST = 0X43
REF_NULL = 0XD0
REF_IS_NULL = 0XD1
REF_FUNC = 0XD2
REF_EQ = 0XD3
REF_AS_NON_NULL = 0XD4
BR_ON_NULL = 0XD5
BR_ON_NON_NULL = 0XD6
GET_LOCAL = 0X20
SET_LOCAL = 0X21
TEE_LOCAL = 0X22
GET_GLOBAL = 0X23
SET_GLOBAL = 0X24
TABLE_GET = 0X25
TABLE_SET = 0X26
CALL = 0X10
CALL_INDIRECT = 0X11
CALL_REF = 0X14
TAIL_CALL = 0X12
TAIL_CALL_INDIRECT = 0X13
TAIL_CALL_REF = 0X15
I32_LOAD8_S = 0X2C
I32_LOAD8_U = 0X2D
I32_LOAD16_S = 0X2E
I32_LOAD16_U = 0X2F
I64_LOAD8_S = 0X30
I64_LOAD8_U = 0X31
I64_LOAD16_S = 0X32
I64_LOAD16_U = 0X33
I64_LOAD32_S = 0X34
I64_LOAD32_U = 0X35
I32_LOAD = 0X28
I64_LOAD = 0X29
F32_LOAD = 0X2A
F64_LOAD = 0X2B
I32_STORE8 = 0X3A
I32_STORE16 = 0X3B
I64_STORE8 = 0X3C
I64_STORE16 = 0X3D
I64_STORE32 = 0X3E
I32_STORE = 0X36
I64_STORE = 0X37
F32_STORE = 0X38
F64_STORE = 0X39
CURRENT_MEMORY = 0X3F
GROW_MEMORY = 0X40
I32_ADD = 0X6A
I32_SUB = 0X6B
I32_MUL = 0X6C
I32_DIV_S = 0X6D
I32_DIV_U = 0X6E
I32_REM_S = 0X6F
I32_REM_U = 0X70
I32_AND = 0X71
I32_OR = 0X72
I32_XOR = 0X73
I32_SHL = 0X74
I32_SHR_U = 0X76
I32_SHR_S = 0X75
I32_ROTR = 0X78
I32_ROTL = 0X77
I32_EQ = 0X46
I32_NE = 0X47
I32_LT_S = 0X48
I32_LE_S = 0X4C
I32_LT_U = 0X49
I32_LE_U = 0X4D
I32_GT_S = 0X4A
I32_GE_S = 0X4E
I32_GT_U = 0X4B
I32_GE_U = 0X4F
I32_CLZ = 0X67
I32_CTZ = 0X68
I32_POPCNT = 0X69
I32_EQZ = 0X45
I64_ADD = 0X7C
I64_SUB = 0X7D
I64_MUL = 0X7E
I64_DIV_S = 0X7F
I64_DIV_U = 0X80
I64_REM_S = 0X81
I64_REM_U = 0X82
I64_AND = 0X83
I64_OR = 0X84
I64_XOR = 0X85
I64_SHL = 0X86
I64_SHR_U = 0X88
I64_SHR_S = 0X87
I64_ROTR = 0X8A
I64_ROTL = 0X89
I64_EQ = 0X51
I64_NE = 0X52
I64_LT_S = 0X53
I64_LE_S = 0X57
I64_LT_U = 0X54
I64_LE_U = 0X58
I64_GT_S = 0X55
I64_GE_S = 0X59
I64_GT_U = 0X56
I64_GE_U = 0X5A
I64_CLZ = 0X79
I64_CTZ = 0X7A
I64_POPCNT = 0X7B
I64_EQZ = 0X50
F32_ADD = 0X92
F32_SUB = 0X93
F32_MUL = 0X94
F32_DIV = 0X95
F32_MIN = 0X96
F32_MAX = 0X97
F32_ABS = 0X8B
F32_NEG = 0X8C
F32_COPYSIGN = 0X98
F32_CEIL = 0X8D
F32_FLOOR = 0X8E
F32_TRUNC = 0X8F
F32_NEAREST = 0X90
F32_SQRT = 0X91
F32_EQ = 0X5B
F32_NE = 0X5C
F32_LT = 0X5D
F32_LE = 0X5F
F32_GT = 0X5E
F32_GE = 0X60
F64_ADD = 0XA0
F64_SUB = 0XA1
F64_MUL = 0XA2
F64_DIV = 0XA3
F64_MIN = 0XA4
F64_MAX = 0XA5
F64_ABS = 0X99
F64_NEG = 0X9A
F64_COPYSIGN = 0XA6
F64_CEIL = 0X9B
F64_FLOOR = 0X9C
F64_TRUNC = 0X9D
F64_NEAREST = 0X9E
F64_SQRT = 0X9F
F64_EQ = 0X61
F64_NE = 0X62
F64_LT = 0X63
F64_LE = 0X65
F64_GT = 0X64
F64_GE = 0X66
I32_TRUNC_S_F32 = 0XA8
I32_TRUNC_S_F64 = 0XAA
I32_TRUNC_U_F32 = 0XA9
I32_TRUNC_U_F64 = 0XAB
I32_WRAP_I64 = 0XA7
I64_TRUNC_S_F32 = 0XAE
I64_TRUNC_S_F64 = 0XB0
I64_TRUNC_U_F32 = 0XAF
I64_TRUNC_U_F64 = 0XB1
I64_EXTEND_S_I32 = 0XAC
I64_EXTEND_U_I32 = 0XAD
F32_CONVERT_S_I32 = 0XB2
F32_CONVERT_U_I32 = 0XB3
F32_CONVERT_S_I64 = 0XB4
F32_CONVERT_U_I64 = 0XB5
F32_DEMOTE_F64 = 0XB6
F32_REINTERPRET_I32 = 0XBE
F64_CONVERT_S_I32 = 0XB7
F64_CONVERT_U_I32 = 0XB8
F64_CONVERT_S_I64 = 0XB9
F64_CONVERT_U_I64 = 0XBA
F64_PROMOTE_F32 = 0XBB
F64_REINTERPRET_I64 = 0XBF
I32_REINTERPRET_F32 = 0XBC
I64_REINTERPRET_F64 = 0XBD
I32_EXTEND8_S = 0XC0
I32_EXTEND16_S = 0XC1
I64_EXTEND8_S = 0XC2
I64_EXTEND16_S = 0XC3
I64_EXTEND32_S = 0XC4