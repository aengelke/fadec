
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <fadec.h>
#include <string.h>

static PyObject* DecodeError;

static unsigned Reg_FromPair(unsigned idx, unsigned ty) {
  return idx == FD_REG_NONE ? 0 : idx | (ty << 8);
}
static PyObject* Reg_AsLong(unsigned reg) {
  return Py_BuildValue(&"I"[!reg], reg);
}

typedef struct {
  PyObject_HEAD

  uint8_t size;
  uint8_t type;
  uint8_t idx;
} RegObject;

typedef struct {
  PyObject_HEAD

  FdInstr fdi;
} InstObject;

typedef struct {
  PyObject_HEAD

  InstObject* inst;
  unsigned idx;
} OpObject;

static PyObject* Reg_str(RegObject* self) {
  char buf[16];
  fd_format_reg(self->type, self->idx, self->size, buf);
  return Py_BuildValue("s", buf);
}

static PyObject* Reg_repr(RegObject* self) {
  char buf[16];
  fd_format_reg(self->type, self->idx, self->size, buf);
  char repr[256];
  sprintf(repr, "<fadec.Reg \"%s\",size=%u,type=%u,idx=%u>", buf, self->size,
          self->type, self->idx);
  return Py_BuildValue("s", repr);
}

static PyMemberDef RegType_members[] = {
    {"sizelg", Py_T_UBYTE, offsetof(RegObject, size), Py_READONLY,
     "Register size (logarithmic)."},
    {"type", Py_T_UBYTE, offsetof(RegObject, type), Py_READONLY,
     "Register type."},
    {"idx", Py_T_UBYTE, offsetof(RegObject, idx), Py_READONLY,
     "Register index."},
    {0}};

static PyTypeObject RegType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "fadec.Reg",
    .tp_doc = "A register",
    .tp_basicsize = sizeof(RegObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_str = (reprfunc)Reg_str,
    .tp_repr = (reprfunc)Reg_repr,
    .tp_members = RegType_members,
};

static void Op_dealloc(PyObject* self) {
  Py_XDECREF(((OpObject*)self)->inst);
  Py_TYPE(self)->tp_free(self);
}

static PyObject* Op_repr(OpObject* self) {
  char buf[128];
  fd_format(&self->inst->fdi, buf, sizeof buf);
  char repr[256];
  sprintf(repr, "<fadec.Op \"%s\",idx=%u>", buf, self->idx);
  return Py_BuildValue("s", repr);
}

static PyObject* Op_getis_type(OpObject* self, void* closure) {
  return PyBool_FromLong(FD_OP_TYPE(&self->inst->fdi, self->idx) ==
                         (uintptr_t)closure);
}
static PyObject* Op_getsize(OpObject* self, void* Py_UNUSED(closure)) {
  return PyLong_FromLong(FD_OP_SIZE(&self->inst->fdi, self->idx));
}
static PyObject* Op_getreg(OpObject* self, void* Py_UNUSED(closure)) {
  if (FD_OP_TYPE(&self->inst->fdi, self->idx) != FD_OT_REG) {
    PyErr_SetString(PyExc_AttributeError, "reg");
    return NULL;
  }
  RegObject* reg = (RegObject*)PyType_GenericAlloc(&RegType, 0);
  if (reg) {
    reg->size = FD_OP_SIZELG(&self->inst->fdi, self->idx);
    reg->type = FD_OP_REG_TYPE(&self->inst->fdi, self->idx);
    reg->idx = FD_OP_REG(&self->inst->fdi, self->idx);
  }
  return (PyObject*)reg;
}
static PyObject* Op_getimm(OpObject* self, void* closure) {
  FdOpType exp_ty = *(const char*)closure == 'o' ? FD_OT_OFF : FD_OT_IMM;
  if (FD_OP_TYPE(&self->inst->fdi, self->idx) != exp_ty) {
    PyErr_SetString(PyExc_AttributeError, (const char*)closure);
    return NULL;
  }
  return PyLong_FromLong(FD_OP_IMM(&self->inst->fdi, self->idx));
}
static PyObject* Op_getbase(OpObject* self, void* Py_UNUSED(closure)) {
  FdOpType ot = FD_OP_TYPE(&self->inst->fdi, self->idx);
  if (ot != FD_OT_MEM && ot != FD_OT_MEMBCST) {
    PyErr_SetString(PyExc_AttributeError, "base");
    return NULL;
  }
  if (FD_OP_BASE(&self->inst->fdi, self->idx) == FD_REG_NONE)
    Py_RETURN_NONE;
  RegObject* reg = (RegObject*)PyType_GenericAlloc(&RegType, 0);
  if (reg) {
    reg->size = FD_ADDRSIZELG(&self->inst->fdi);
    reg->type = FD_RT_GPL;
    reg->idx = FD_OP_BASE(&self->inst->fdi, self->idx);
  }
  return (PyObject*)reg;
}
static PyObject* Op_getindex(OpObject* self, void* Py_UNUSED(closure)) {
  FdOpType ot = FD_OP_TYPE(&self->inst->fdi, self->idx);
  if (ot != FD_OT_MEM && ot != FD_OT_MEMBCST) {
    PyErr_SetString(PyExc_AttributeError, "base");
    return NULL;
  }
  if (FD_OP_INDEX(&self->inst->fdi, self->idx) == FD_REG_NONE)
    Py_RETURN_NONE;
  RegObject* reg = (RegObject*)PyType_GenericAlloc(&RegType, 0);
  if (reg) {
    // TODO: VSIB
    reg->size = FD_ADDRSIZELG(&self->inst->fdi);
    reg->type = FD_RT_GPL;
    reg->idx = FD_OP_INDEX(&self->inst->fdi, self->idx);
  }
  return (PyObject*)reg;
}
static PyObject* Op_getscale(OpObject* self, void* Py_UNUSED(closure)) {
  FdOpType ot = FD_OP_TYPE(&self->inst->fdi, self->idx);
  if ((ot != FD_OT_MEM && ot != FD_OT_MEMBCST) ||
      FD_OP_INDEX(&self->inst->fdi, self->idx) == FD_REG_NONE) {
    PyErr_SetString(PyExc_AttributeError, "scale");
    return NULL;
  }
  return PyLong_FromLong(FD_OP_SCALE(&self->inst->fdi, self->idx));
}
static PyObject* Op_getdisp(OpObject* self, void* Py_UNUSED(closure)) {
  FdOpType ot = FD_OP_TYPE(&self->inst->fdi, self->idx);
  if ((ot != FD_OT_MEM && ot != FD_OT_MEMBCST)) {
    PyErr_SetString(PyExc_AttributeError, "disp");
    return NULL;
  }
  return PyLong_FromLong(FD_OP_DISP(&self->inst->fdi, self->idx));
}
static PyObject* Op_getbcstsz(OpObject* self, void* Py_UNUSED(closure)) {
  if (FD_OP_TYPE(&self->inst->fdi, self->idx) != FD_OT_MEMBCST) {
    PyErr_SetString(PyExc_AttributeError, "bcstsz");
    return NULL;
  }
  return PyLong_FromLong(FD_OP_BCSTSZ(&self->inst->fdi, self->idx));
}

static PyGetSetDef OpType_getset[] = {
    {"is_reg", (getter)Op_getis_type, NULL, "Whether operand is a register",
     (void*)FD_OT_REG},
    {"is_imm", (getter)Op_getis_type, NULL, "Whether operand is an immediate",
     (void*)FD_OT_IMM},
    {"is_mem", (getter)Op_getis_type, NULL,
     "Whether operand refers to a memory location", (void*)FD_OT_MEM},
    {"is_off", (getter)Op_getis_type, NULL,
     "Whether operand is relative offset", (void*)FD_OT_OFF},
    {"is_membcst", (getter)Op_getis_type, NULL,
     "Whether operand refers to a broadcasted memory location",
     (void*)FD_OT_MEMBCST},
    {"size", (getter)Op_getsize, NULL, "Operand size (in bytes, or zero)",
     NULL},
    {"reg", (getter)Op_getreg, NULL, "Register value (for register operands)",
     NULL},
    {"imm", (getter)Op_getimm, NULL,
     "Immediate operand (for immediate operands)", (void*)"imm"},
    {"off", (getter)Op_getimm, NULL, "Offset operand (for offset operands)",
     (void*)"off"},
    {"base", (getter)Op_getbase, NULL, "Base register (for memory operands)",
     NULL},
    {"index", (getter)Op_getindex, NULL, "Index register (for memory operands)",
     NULL},
    {"scale", (getter)Op_getscale, NULL, "Scale (for memory operands)", NULL},
    {"disp", (getter)Op_getdisp, NULL, "Displacement (for memory operands)",
     NULL},
    {"bcstsz", (getter)Op_getbcstsz, NULL, "Broadcast size (in bytes)", NULL},
    {0}};

static PyTypeObject OpType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "fadec.Op",
    .tp_doc = "An instruction operand",
    .tp_basicsize = sizeof(OpObject),
    .tp_itemsize = 0,
    .tp_dealloc = Op_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_repr = (reprfunc)Op_repr,
    .tp_getset = OpType_getset,
};

static PyObject* Inst_str(InstObject* self) {
  char buf[128];
  fd_format(&self->fdi, buf, sizeof buf);
  return Py_BuildValue("s", buf);
}

static PyObject* Inst_repr(InstObject* self) {
  char buf[128];
  fd_format(&self->fdi, buf, sizeof buf);
  char repr[256];
  sprintf(repr, "<fadec.Inst \"%s\",size=%u>", buf, FD_SIZE(&self->fdi));
  return Py_BuildValue("s", repr);
}

static PyObject* Inst_gettype(InstObject* self, void* Py_UNUSED(closure)) {
  return PyLong_FromLong(FD_TYPE(&self->fdi));
}

static PyObject* Inst_getsize(InstObject* self, void* Py_UNUSED(closure)) {
  return PyLong_FromLong(FD_SIZE(&self->fdi));
}

static PyObject* Inst_getsegment(InstObject* self, void* Py_UNUSED(closure)) {
  return Reg_AsLong(Reg_FromPair(FD_SEGMENT(&self->fdi), FD_RT_SEG));
}

static PyObject* Inst_getopsize(InstObject* self, void* Py_UNUSED(closure)) {
  return PyLong_FromLong(FD_OPSIZE(&self->fdi));
}

static PyObject* Inst_getaddrsize(InstObject* self, void* Py_UNUSED(closure)) {
  return PyLong_FromLong(FD_ADDRSIZE(&self->fdi));
}

static PyObject* Inst_gethas_rep(InstObject* self, void* Py_UNUSED(closure)) {
  return PyBool_FromLong(FD_HAS_REP(&self->fdi));
}

static PyObject* Inst_gethas_repnz(InstObject* self, void* Py_UNUSED(closure)) {
  return PyBool_FromLong(FD_HAS_REPNZ(&self->fdi));
}

static PyObject* Inst_gethas_lock(InstObject* self, void* Py_UNUSED(closure)) {
  return PyBool_FromLong(FD_HAS_LOCK(&self->fdi));
}

static PyObject* Inst_gethas_3e(InstObject* self, void* Py_UNUSED(closure)) {
  return PyBool_FromLong(FD_HAS_3E(&self->fdi));
}

static PyObject* Inst_getmaskreg(InstObject* self, void* Py_UNUSED(closure)) {
  unsigned maskreg =
      FD_MASKREG(&self->fdi) ? FD_MASKREG(&self->fdi) : FD_REG_NONE;
  return Reg_AsLong(Reg_FromPair(maskreg, FD_RT_MASK));
}

static PyObject* Inst_getmaskzero(InstObject* self, void* Py_UNUSED(closure)) {
  if (FD_MASKREG(&self->fdi) == 0) {
    PyErr_SetString(PyExc_AttributeError, "maskzero");
    return NULL;
  }
  return PyBool_FromLong(FD_MASKZERO(&self->fdi));
}

static PyObject* Inst_getops(InstObject* self, void* Py_UNUSED(closure)) {
  const FdInstr* fdi = &self->fdi;
  unsigned num_ops = 0;
  for (; num_ops < 4; num_ops++)
    if (FD_OP_TYPE(fdi, num_ops) == FD_OT_NONE)
      break;

  PyObject* res = PyTuple_New(num_ops);
  for (unsigned idx = 0; idx < num_ops; idx++) {
    OpObject* op = (OpObject*)PyType_GenericAlloc(&OpType, 0);
    if (op == NULL) {
      Py_DECREF(res);
      return NULL;
    }
    Py_INCREF(self);
    op->inst = self;
    op->idx = idx;
    PyTuple_SetItem(res, idx, (PyObject*)op);
  }
  return res;
}

static PyObject* Inst_getroundcontrol(InstObject* self,
                                      void* Py_UNUSED(closure)) {
  return PyLong_FromLong(FD_ROUNDCONTROL(&self->fdi));
}

static PyGetSetDef InstType_getset[] = {
    {"type", (getter)Inst_gettype, NULL,
     "The type/mnemonic of the instruction.", NULL},
    {"size", (getter)Inst_getsize, NULL,
     "The size of the instruction in bytes.", NULL},
    {"segment", (getter)Inst_getsegment, NULL,
     "The specified segment override register, or None.", NULL},
    {"addrsize", (getter)Inst_getaddrsize, NULL,
     "The address size attribute of the instruction in bytes.", NULL},
    {"opsize", (getter)Inst_getopsize, NULL,
     "The operation width in bytes of the instruction if this is not encoded "
     "in the operands, for example for the string instruction (e.g. MOVS).",
     NULL},
    {"has_rep", (getter)Inst_gethas_rep, NULL,
     "Whether the instruction was encoded with a REP prefix. Needed for: "
     "(1) Handling the instructions MOVS, STOS, LODS, INS and OUTS properly. "
     "(2) Handling the instructions SCAS and CMPS, for which this means REPZ.",
     NULL},
    {"has_repnz", (getter)Inst_gethas_repnz, NULL,
     "Whether the instruction was encoded with a REPNZ prefix.", NULL},
    {"has_lock", (getter)Inst_gethas_lock, NULL,
     "Whether the instruction was encoded with a LOCK prefix.", NULL},
    {"has_3e", (getter)Inst_gethas_3e, NULL,
     "whether there is a meaningful 3E prefix used for indirect JMP (notrack "
     "prefix) and conditional branches (hint-taken prefix).",
     NULL},
    {"maskreg", (getter)Inst_getmaskreg, NULL,
     "The opmask register for EVEX-encoded instructions; None for no mask.",
     NULL},
    {"maskzero", (getter)Inst_getmaskzero, NULL,
     "Whether zero masking shall be used.", NULL},
    {"roundcontrol", (getter)Inst_getroundcontrol, NULL,
     "The rounding mode for EVEX-encoded instructions.", NULL},
    {"ops", (getter)Inst_getops, NULL, "The instruction operands.", NULL},
    {0}};

static PyTypeObject InstType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "fadec.Inst",
    .tp_doc = "A decoded instruction",
    .tp_basicsize = sizeof(InstObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_str = (reprfunc)Inst_str,
    .tp_repr = (reprfunc)Inst_repr,
    .tp_getset = InstType_getset,
};

static PyObject* decode_generic(PyObject* Py_UNUSED(self), PyObject* args,
                                int mode) {
  Py_buffer buf;
  if (!PyArg_ParseTuple(args, "y*", &buf))
    return NULL;

  InstObject* inst = (InstObject*)PyType_GenericAlloc(&InstType, 0);
  if (inst != NULL) {
    int res = fd_decode(buf.buf, buf.len, mode, 0, &inst->fdi);
    if (res < 0) {
      PyErr_SetString(DecodeError, "Decoding failed");
      Py_DECREF(inst);
      PyBuffer_Release(&buf);
      return NULL;
    }
  }

  PyBuffer_Release(&buf);
  return (PyObject*)inst;
}

static PyObject* decode32(PyObject* self, PyObject* args) {
  return decode_generic(self, args, 32);
}

static PyObject* decode64(PyObject* self, PyObject* args) {
  return decode_generic(self, args, 64);
}

static PyMethodDef FadecMethods[] = {
    {"decode32", decode32, METH_VARARGS, "Decode for 32-bit mode."},
    {"decode64", decode64, METH_VARARGS, "Decode for 64-bit mode."},
    {0}};

static struct PyModuleDef fadecmodule = {
    PyModuleDef_HEAD_INIT,
    "fadec",
    "Fadec: fast decoder/encoder for x86(-64)",
    -1,
    FadecMethods,
};

static int add_const(PyObject* dict, const char* name, unsigned value) {
  PyObject* val = PyLong_FromLong(value);
  if (val == NULL)
    return -1;
  if (PyDict_SetItemString(dict, name, val) < 0)
    return -1;
  Py_DECREF(val);
  return 0;
}

static PyObject* create_reg_dict(void) {
  // TODO: reduce code size
  PyObject* reg_dict = PyDict_New();
#define REG_TY(ty)                                                             \
  if (add_const(reg_dict, #ty, FD_RT_##ty) < 0)                                \
    goto fail;
  REG_TY(VEC)
  REG_TY(GPL)
  REG_TY(GPH)
  REG_TY(SEG)
  REG_TY(FPU)
  REG_TY(MMX)
  REG_TY(TMM)
  REG_TY(MASK)
  REG_TY(BND)
  REG_TY(CR)
  REG_TY(DR)
#undef REG_TY
  return reg_dict;

fail:
  Py_DECREF(reg_dict);
  return NULL;
}

static PyObject* create_inst_dict(void) {
  // TODO: reduce code size
  PyObject* inst_dict = PyDict_New();
#define FD_MNEMONIC(name, value)                                               \
  if (add_const(inst_dict, #name, value) < 0)                                  \
    goto fail;
#include <fadec-decode-public.inc>
#undef FD_MNEMONIC
  return inst_dict;

fail:
  Py_DECREF(inst_dict);
  return NULL;
}

PyMODINIT_FUNC PyInit_fadec(void) {
  if (PyType_Ready(&OpType) < 0)
    return NULL;

  Py_XDECREF(RegType.tp_dict);
  RegType.tp_dict = create_reg_dict();
  if (!RegType.tp_dict)
    return NULL;
  if (PyType_Ready(&RegType) < 0) {
    Py_CLEAR(RegType.tp_dict);
    return NULL;
  }

  Py_XDECREF(InstType.tp_dict);
  InstType.tp_dict = create_inst_dict();
  if (!InstType.tp_dict)
    return NULL;
  if (PyType_Ready(&InstType) < 0) {
    Py_CLEAR(InstType.tp_dict);
    return NULL;
  }

  PyObject* m = PyModule_Create(&fadecmodule);
  if (m == NULL)
    return NULL;

  Py_INCREF(&InstType);
  if (PyModule_AddObject(m, "Inst", (PyObject*)&InstType) < 0) {
    Py_DECREF(&InstType);
    Py_DECREF(m);
    return NULL;
  }

  Py_INCREF(&OpType);
  if (PyModule_AddObject(m, "Op", (PyObject*)&OpType) < 0) {
    Py_DECREF(&OpType);
    Py_DECREF(m);
    return NULL;
  }

  Py_INCREF(&RegType);
  if (PyModule_AddObject(m, "Reg", (PyObject*)&RegType) < 0) {
    Py_DECREF(&RegType);
    Py_DECREF(m);
    return NULL;
  }

  DecodeError = PyErr_NewException("fadec.DecodeError", NULL, NULL);
  if (DecodeError == NULL) {
    Py_DECREF(m);
    return NULL;
  }
  Py_XINCREF(DecodeError);
  if (PyModule_AddObject(m, "DecodeError", DecodeError) < 0) {
    Py_XDECREF(DecodeError);
    Py_CLEAR(DecodeError);
    Py_DECREF(m);
    return NULL;
  }

  return m;
}
