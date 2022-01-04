#pragma once

#include <fstream>
#include <windows.h>

class c_pe_file {
 public:
  IMAGE_DOS_HEADER dos{};
  IMAGE_NT_HEADERS nt{};

  c_pe_file(const std::string &path) {
    std::ifstream file{path, std::ios::binary};
    if (!file.is_open()) 
      throw std::runtime_error("Failed to open");

    file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (dos.e_magic != 0x5A4D)
      throw std::runtime_error("Not executable file");

    file.seekg(dos.e_lfanew);
    file.read(reinterpret_cast<char*>(&nt), sizeof(nt));
    if (nt.Signature != 0x4550)
      throw std::runtime_error("Not executable file");
  }
};