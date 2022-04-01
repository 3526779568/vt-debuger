#pragma once

extern "C" {
#include <Windows.h>
#include <keystone/keystone.h>
#include <Zydis/Zydis.h>

//#pragma comment( \
//    lib, "C:\\Users\\bing\\Downloads\\keystone-0.9.1-win32\\keystone.lib")
#pragma comment(lib, "E:\\lib\\Debug\\x64\\keystone.lib")
#pragma comment(lib, "E:\\lib\\Debug\\x64\\Zydis.lib")
class Compiler {
 public:
  Compiler(const char *code);
  ~Compiler();
  void print_bin_code();
  void print_str_code(ZyanU64 runtime_address);
  bool RelocalInstruction(ZyanU64 runtime_address, const char *ins_strstr,
                          ZyanU64 go_to, ZyanU64 bit_num = 0,
                          ZyanU64 operands = 0, ZyanBool don_t_offset = FALSE);

 public:
  ks_engine *ks{0};
  unsigned char *encode{0};
  size_t count{0};
  size_t size{0};
  ks_err err;
  ZydisDecoder decoder;
  ZydisFormatter formatter;
};

inline Compiler::Compiler(const char *code) {
  auto err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
  if (err != KS_ERR_OK) {
    printf("ERROR: failed on ks_open(), quit\n");
    return;
  }

  if (ks_asm(ks, code, 0, &encode, &size, &count) != KS_ERR_OK) {
    printf("ERROR: ks_asm() failed & count = %lu, error = %u\n", count,
           ks_errno(ks));
  }

  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32,
                   ZYDIS_ADDRESS_WIDTH_32);
  ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
}

inline Compiler::~Compiler() {
  // NOTE: free encode after usage to avoid leaking memory
  ks_free(encode);

  // close Keystone instance when done
  ks_close(ks);
}
inline void Compiler::print_bin_code() {
  for (size_t i = 0; i < size; i++) {
    printf("%#x,", encode[i]);
  }
  printf("\n");
}
inline void Compiler::print_str_code(ZyanU64 runtime_address) {
  char *buff = (char *)this->encode;
  int length = this->size;
  ZyanUSize offset = 0;
  ZydisDecodedInstruction instruction;
  while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
      &decoder, buff + offset, length - offset, &instruction))) {
    // Format & print the binary instruction structure to human readable format
    char buffer[256];
    ZydisFormatterFormatInstruction(&formatter, &instruction, buffer,
                                    sizeof(buffer), runtime_address);
    puts(buffer);

    offset += instruction.length;
    runtime_address += instruction.length;
  }
}
inline bool Compiler::RelocalInstruction(ZyanU64 runtime_address,
                                         const char *ins_strstr, ZyanU64 go_to,
                                         ZyanU64 bit_num, ZyanU64 operands,
                                         ZyanBool don_t_offset) {
  // char &buff[] = this->encode;
  int length = this->size;
  ZyanUSize offset = 0;
  ZyanU64 count = 0;
  ZydisDecodedInstruction instruction;
  while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
      &decoder, this->encode + offset, length - offset, &instruction))) {
    // Format & print the binary instruction structure to human readable format
    char buffer[256];
    ZydisFormatterFormatInstruction(&formatter, &instruction, buffer,
                                    sizeof(buffer), runtime_address);
    if (strstr(buffer, ins_strstr) != nullptr) {
      // found it
      if (count == bit_num) {
        if (!don_t_offset) {
          int inst_offset = go_to - runtime_address - instruction.length;
          if (instruction.raw.imm[operands].size) {
            *(int *)&this
                 ->encode[offset + instruction.raw.imm[operands].offset] =
                inst_offset;
          } else {
            *(int *)&this->encode[offset + instruction.raw.disp.offset] =
                inst_offset;
          }

        } else {  //不需要计算相对偏移的指令
          if (instruction.raw.imm[operands].size) {
            *(int *)&this
                 ->encode[offset + instruction.raw.imm[operands].offset] =
                (int)go_to;
          } else {
            *(int *)&this->encode[offset + instruction.raw.disp.offset] =
                (int)go_to;
          }
        }
        return true;
      }
      count++;
    }
    offset += instruction.length;
    runtime_address += instruction.length;
  }
  return false;
}
}