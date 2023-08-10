#include <cstdint>
#include <cstring>
#include <ios>
#include <iostream>
#include <memory>
#include <vector>

#include "loadimage.hh"
#include "opcodes.hh"
#include "pcoderaw.hh"
#include "sleigh.hh"
#include "space.hh"
#include "translate.hh"
#include "xml.hh"

struct VarnodeDesc {
  char space[16];
  uint64_t offset;
  uint64_t size;
};

struct PcodeOp {
  ghidra::OpCode opcode;
  VarnodeDesc *output;
  uint64_t input_len;
  VarnodeDesc *inputVarnodes;
};

struct InsnDesc {
  uint64_t op_count;
  PcodeOp *ops;
  uint64_t size;
  uint64_t address;
  char *insn;
  uint64_t insn_len;
  char *body;
  uint64_t body_len;
};

struct RegisterDesc {
  char name[64];
  VarnodeDesc varnode;
};

struct RegisterList {
  uint64_t register_count;
  RegisterDesc *registers;
};

struct UserOpNames {
  uint64_t num;
  uint64_t *name_lens;
  char **names;
};

class ArbitraryAsmEmitter : public ghidra::AssemblyEmit {
public:
  uint64_t insn_size;
  uint64_t address;
  char *insn_text;
  uint64_t insn_text_len;
  char *insn_body;
  uint64_t insn_body_len;

  ArbitraryAsmEmitter(void) : ghidra::AssemblyEmit() {}
  void clear(void) {
    insn_size = 0;
    address = 0;
    insn_text = nullptr;
    insn_text_len = 0;
    insn_body = nullptr;
    insn_body_len = 0;
  }

  /**
   * \brief dumps the current instruction from SLEIGH into the
   * instance variables.
   * NOTE: this has no concept of insn length and the `ArbitraryManger`
   * will need to set that
   * */
  virtual void dump(const ghidra::Address &addr, const ghidra::string &text,
                    const ghidra::string &body) {
    address = addr.getOffset(); // offset into code space is our "address"
    insn_text = strdup(text.c_str());
    insn_text_len = text.size();
    insn_body = strdup(body.c_str());
    insn_body_len = body.size();
  }
};

class ArbitraryPcodeEmitter : public ghidra::PcodeEmit {
public:
  std::vector<PcodeOp> pcode_ops;
  ArbitraryPcodeEmitter(void) : ghidra::PcodeEmit() { pcode_ops.reserve(64); }

  virtual void dump(const ghidra::Address &addr, ghidra::OpCode opcode,
                    ghidra::VarnodeData *output, ghidra::VarnodeData *inputs,
                    ghidra::int4 input_len) {
    pcode_ops.emplace_back();
    PcodeOp &op = pcode_ops.back();

    op.opcode = opcode;
    op.input_len = (uint64_t)input_len;

    // copy the n input nodes
    VarnodeDesc *input_descs = new (std::nothrow) VarnodeDesc[input_len];
    for (int i = 0; i < input_len; i++) {
      ghidra::VarnodeData input_node = inputs[i];
      input_descs[i].offset = input_node.offset;
      input_descs[i].size = input_node.size;
      strncpy(input_descs[i].space, input_node.space->getName().c_str(),
              sizeof(input_descs[i].space));
    }
    op.inputVarnodes = input_descs;

    // now get the output metadata is there is an output node
    if (output != nullptr) {
      op.output = new (std::nothrow) VarnodeDesc;
      op.output->offset = output->offset;
      op.output->size = output->size;
      strncpy(op.output->space, output->space->getName().c_str(),
              sizeof(op.output->space));
    } else {
      // not output node
      op.output = nullptr;
    }
  }
};

/// Loader for holding regions we want to be able to translate.
/// Note that this has the (poor) behavior of filling in nulls if there
/// if a requested address between our min + max that we don't have an
/// explicit backing for.
class ArbitraryLoader : public ghidra::LoadImage {
  // maximum address of any region
  uint64_t max_addr = 0;
  // minimum address of any region
  uint64_t min_addr = 0xffffffffffffffff;

  struct MemoryDescription {
    uint64_t base_address;
    uint64_t size;
    uint8_t *data;
  };

  // this holds the list of memory regions we're working with
  std::vector<MemoryDescription *> regions;

public:
  ArbitraryLoader(void) : ghidra::LoadImage("nofile") {}
  virtual void loadFill(ghidra::uint1 *ptr, ghidra::int4 size,
                        const ghidra::Address &addr);
  virtual std::string getArchType(void) const { return "none"; }
  virtual void adjustVma(long adjust) {}

  // finds and returns the minimum address of all the memory regions
  uint64_t base(void) {
    uint64_t base = UINT64_MAX;

    std::vector<MemoryDescription *>::iterator it;
    for (it = regions.begin(); it != regions.end(); it++) {
      uint64_t iter_base = (*it.base())->base_address;
      if (iter_base < base) {
        base = iter_base;
      }
    }

    return base;
  }

  // adds a region to the internal store
  void load_region(uint64_t address, uint64_t size, uint8_t *input_data) {
    MemoryDescription *desc = new MemoryDescription;
    desc->base_address = address;
    desc->size = size;
    desc->data = input_data;
    regions.push_back(desc);

    // adjust minimum address
    if (address < min_addr) {
      min_addr = address;
    }

    // adjust maximum address
    if (address + size > max_addr) {
      max_addr = address + size;
    }
  }

  // given an address, return which of our region's owns it,
  // null otherwise
  MemoryDescription *region_from_address(uint64_t address) {
    std::vector<MemoryDescription *>::iterator it;
    for (it = regions.begin(); it != regions.end(); it++) {
      MemoryDescription *guess = *it.base();

      // this region starts higher than the address
      if (guess->base_address > address) {
        continue;
      }

      // this region ends before the address
      if (guess->base_address + guess->size <= address) {
        continue;
      }

      // this is the correct region
      return guess;
    }

    return nullptr;
  }
};

/** \brief basically just follow the example `loadFill` except fixes the inner
 * loop extra math garbage. Note that ghidra is going to have 1 loader per
 * address space...so things may get hectic here since we need to fake it
 */
void ArbitraryLoader::loadFill(ghidra::uint1 *ptr, ghidra::int4 size,
                               const ghidra::Address &addr) {
  // use this to keep track of data left across region boundaries
  int32_t bytes_remaining = size;
  uint64_t search_address = addr.getOffset();
  uint8_t *out = (uint8_t *)ptr;
  uint64_t write_idx = 0;

  // too big
  if (search_address > max_addr) {
    return;
  }

  // keep looping through memory regions until we've copied all the data
  while (bytes_remaining > 0) {
    // get the region that own the index that houses theh requested
    // start address
    MemoryDescription *region = region_from_address(search_address);

    // no region owns this address, write a null byte until we're done
    if (region == nullptr) {

      out[write_idx] = 0;

      // adjust counters
      write_idx++;
      search_address++;
      bytes_remaining--;
      continue;
    }

    // get the region index to start at
    uint64_t region_index = search_address - region->base_address;

    // copy all the data from the current region until we:
    // - hit the end of the section
    // - copy the necessary bytes
    for (uint64_t i = region_index; i < region->size && bytes_remaining > 0;
         i++) {
      out[write_idx] = region->data[i];

      // adjust counters
      write_idx++;
      search_address++;
      bytes_remaining--;
    }
  }
}

class ArbitraryManager {
  ArbitraryLoader loader;
  ArbitraryPcodeEmitter pcode_emitter;
  ArbitraryAsmEmitter asm_emitter;
  ghidra::DocumentStorage document_storage;
  ghidra::ContextInternal context; // TODO: make impl of this
  ghidra::Document *document;
  ghidra::Element *root_node;
  std::unique_ptr<ghidra::Sleigh> sleigh;
  uint64_t current_translate_address = 0;

public:
  ArbitraryManager(void) {
    // initialize ghidra globals
    ghidra::AttributeId::initialize();
    ghidra::ElementId::initialize();

    // setup instance variables
    sleigh.reset(new ghidra::Sleigh(&loader, &context)); // init unique_ptr
  }

  void begin(void) {
    // given that we've already setup the spec file, the loaded image,
    // start the thing frfr
    sleigh->initialize(document_storage);
  }

  void load_specfile(char path[]) {
    document = document_storage.openDocument(path);
    root_node = document->getRoot();
    document_storage.registerTag(root_node);
  }

  void reset(void) {
    sleigh.reset(new ghidra::Sleigh(&loader, &context));
    sleigh->initialize(document_storage);
  }

  void load_data(uint64_t address, uint64_t size, uint8_t *data) {
    loader.load_region(address, size, data);
  }

  InsnDesc *to_insn_desc(void) {
    // build the innitial desc from the pcodeemit class
    InsnDesc *out = new (std::nothrow) InsnDesc;
    out->op_count = pcode_emitter.pcode_ops.size();
    out->ops = new (std::nothrow) PcodeOp[out->op_count];
    memcpy(out->ops, pcode_emitter.pcode_ops.data(),
           sizeof(PcodeOp) * pcode_emitter.pcode_ops.size());

    // now add the details from the asm emit
    out->size = asm_emitter.insn_size;
    out->insn = asm_emitter.insn_text;
    out->insn_len = asm_emitter.insn_text_len;
    out->body = asm_emitter.insn_body;
    out->body_len = asm_emitter.insn_body_len;

    return out;
  }

  InsnDesc *translate_next(void) {
    if (current_translate_address == 0) {
      current_translate_address = loader.base();
    }
    ghidra::Address address(sleigh->getDefaultCodeSpace(),
                            current_translate_address);
    // setup the asm for the insn
    sleigh->printAssembly(asm_emitter, address);
    int32_t insn_length = sleigh->oneInstruction(pcode_emitter, address);

    // set the length of the asm_emitter so it has context
    asm_emitter.insn_size = insn_length;

    // increase for next iteration
    current_translate_address += insn_length;

    // get the current p-code ops + asm from this instruction
    InsnDesc *out = to_insn_desc();

    // clear data from this instruction
    pcode_emitter.pcode_ops.clear();
    asm_emitter.clear();

    // return our populated struct
    return out;
  }

  InsnDesc *lift_insn(uint64_t addr) {
    InsnDesc *out = nullptr;
    try {
      ghidra::Address address(sleigh->getDefaultCodeSpace(), addr);

      // lift the insn
      sleigh->printAssembly(asm_emitter, address);
      int32_t insn_length = sleigh->oneInstruction(pcode_emitter, address);
      asm_emitter.insn_size = insn_length;

      // get the metadata
      out = to_insn_desc();
      out->address = addr;

      // clear insn data
      pcode_emitter.pcode_ops.clear();
      asm_emitter.clear();
    } catch (ghidra::BadDataError &e) {
      // continue
      out = nullptr;
      // std::cout << "BadDataError: " << e.explain << std::endl;
    }

    return out;
  }

  void context_var_set_default(char key[], uint32_t value) {
    context.setVariableDefault(key, value);
  }

  RegisterList *get_all_registers(void) {
    std::map<ghidra::VarnodeData, ghidra::string> register_list;
    sleigh->getAllRegisters(register_list);

    // allocate memory needed to fit all the registers
    RegisterList *out = new (std::nothrow) RegisterList;
    out->register_count = register_list.size();
    out->registers = new (std::nothrow) RegisterDesc[out->register_count];

    // for all the registers in the map, add them to our output
    std::map<ghidra::VarnodeData, ghidra::string>::iterator it;
    uint64_t idx = 0;
    for (it = register_list.begin(); it != register_list.end(); it++, idx++) {
      RegisterDesc *reg = &out->registers[idx];
      ghidra::VarnodeData vn = it->first;
      ghidra::string name = it->second;

      // copy the register name
      strncpy(reg->name, name.c_str(), 64);

      // copy the varnode data
      reg->varnode.offset = vn.offset;
      reg->varnode.size = vn.size;
      strncpy(reg->varnode.space, vn.space->getName().c_str(), 16);
    }

    return out;
  }

  UserOpNames *get_user_ops(void) {
    std::vector<std::string> ops;

    // get the op names
    sleigh->getUserOpNames(ops);

    // now copy and export
    UserOpNames *names = new (std::nothrow) UserOpNames;
    names->num = ops.size();
    names->name_lens = new (std::nothrow) uint64_t[names->num];
    names->names = new (std::nothrow) char *[names->num];

    // not duplicate all the string
    uint64_t idx = 0;
    std::vector<std::string>::iterator it;
    for (it = ops.begin(); it != ops.end(); it++, idx++) {
      std::string n = it->data();
      names->name_lens[idx] = n.size();
      names->names[idx] = strdup(n.c_str());
    }

    return names;
  }
};

/************************************************/
/// C-API begins here
/************************************************/
extern "C" {
/**
 * \brief constructs a new `ArbitraryManager`
 */
ArbitraryManager *arbitrary_manager_new(void) { return new ArbitraryManager{}; }

/**
 * \brief free's the provided `ArbitraryManager`
 */
void arbitrary_manager_free(ArbitraryManager *mgr) { delete mgr; }

/**
 * \brief Loads a sequence of bytes at the provided address
 * inside the underlying `ArbitraryLoader` to the
 * `ArbitraryManager`.
 *
 * *This must be called before `arbitrary_manager_specfile`
 * and `arbitrary_manager_next_insn`*
 */
void arbitrary_manager_load_region(ArbitraryManager *mgr, uint64_t address,
                                   uint64_t size, uint8_t *data) {
  mgr->load_data(address, size, data);
}

/**
 * \brief After loading bytes into the loader, connect the
 * proper specfile at `path` to decode the bytestream.
 */
void arbitrary_manager_specfile(ArbitraryManager *mgr, char path[]) {
  mgr->load_specfile(path);
}

/**
 * \brief After loading bytes and setting the specfile,
 * call this method to kickoff the SLEIGH backend.
 */
void arbitrary_manager_begin(ArbitraryManager *mgr) { mgr->begin(); }

/**
 * \brief After starting the SLEIGH backend, call this method
 * to decode the next instruction, by default it starts at the
 * beginning of the sole provided address space.
 */
InsnDesc *arbitrary_manager_next_insn(ArbitraryManager *mgr) {
  return mgr->translate_next();
}

/**
 * \brief After starting the SLEIGH backend, call this method to
 * decode the instruction at `address`. You probably want to make
 * sure the requested addreess is aligned properly and in the right
 * address space.
 */
InsnDesc *arbitrary_manager_lift_insn(ArbitraryManager *mgr, uint64_t address) {
  return mgr->lift_insn(address);
}

/**
 * \brief set's the context var global default to `value`
 */
void arbitrary_manager_context_var_set_default(ArbitraryManager *mgr,
                                               char key[], uint32_t value) {
  try {
    mgr->context_var_set_default(key, value);
  } catch (ghidra::LowlevelError &err) {
    std::cout << "[libsla ERROR]: " << err.explain << std::endl << std::flush;
  }
}

RegisterList *arbitrary_manager_get_all_registers(ArbitraryManager *mgr) {
  return mgr->get_all_registers();
}

UserOpNames *arbitrary_manager_get_user_ops(ArbitraryManager *mgr) {
  return mgr->get_user_ops();
}
}
