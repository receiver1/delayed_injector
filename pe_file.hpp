#pragma once

#include <fstream>
#include <windows.h>

class c_pe_file {
 public:
  IMAGE_DOS_HEADER dos{};
  IMAGE_NT_HEADERS nt{};

  c_pe_file(std::string path) {
    std::ifstream file{path, std::ios::binary};
    if (file.is_open()) {
      std::string headers{"", 1000};
      file.read(&headers[0], 1000);

      dos = *reinterpret_cast<IMAGE_DOS_HEADER *>(&headers[0]);
      if (dos.e_magic != 0x5A4D)
        throw std::runtime_error("Not executable file");

      nt = *reinterpret_cast<IMAGE_NT_HEADERS *>(&headers[dos.e_lfanew]);
      if (nt.Signature != 0x4550)
        throw std::runtime_error("Not executable file");

      file.close();
    }
  }
};