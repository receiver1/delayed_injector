#pragma once

#include <string>
#include <windows.h>
#include <tlhelp32.h>

#include "ntdef.hpp"
#include "pe_file.hpp"

class c_inject_error : private std::runtime_error {
  int code = 0;

 public:
  c_inject_error(int error) throw()
      : code(error), std::runtime_error(std::to_string(error)) {}
  c_inject_error(const char *error) throw() : std::runtime_error(error) {}
  virtual const char *what() const throw() {
    switch (code) {
      case 0xC0000008:
        return "STATUS_INVALID_HANDLE";
      case 0xC0000017:
        return "STATUS_NO_MEMORY";
      case 0xC0000018:
        return "STATUS_CONFLICTING_ADDRESSES";
      case 0xC0000021:
        return "STATUS_ALREADY_COMMITTED";
      case 0xC0000022:
        return "STATUS_ACCESS_DENIED";
      case 0xC0000024:
        return "STATUS_OBJECT_TYPE_MISMATCH";
      case 0xC00000A0:
        return "STATUS_MEMORY_NOT_ALLOCATED";
      case 0xC000012D:
        return "STATUS_COMMITMENT_LIMIT";
      case 0xC000009A:
        return "STATUS_INSUFFICIENT_RESOURCES";
      case 0xC0000045:
        return "STATUS_INVALID_PAGE_PROTECTION";
      case 0xC000010A:
        return "STATUS_PROCESS_IS_TERMINATING";
      default:
        return exception::what();
    }
  }
};

class c_injector {
  using nt_open_process = NTSTATUS(__stdcall *)(PHANDLE, ACCESS_MASK,
                                                POBJECT_ATTRIBUTES, PCLIENT_ID);
  using nt_close = NTSTATUS(__stdcall *)(HANDLE);
  using nt_allocate_virtual_memory = NTSTATUS(__stdcall *)(HANDLE, PVOID *,
                                                           ULONG, PULONG, ULONG,
                                                           ULONG);
  using nt_free_virtual_memory = NTSTATUS(__stdcall *)(HANDLE, PVOID *, PSIZE_T,
                                                       ULONG);
  using nt_write_virtual_memory = NTSTATUS(__stdcall *)(HANDLE, PVOID, PVOID,
                                                        ULONG, PULONG);

  nt_open_process open;
  nt_close close;
  nt_allocate_virtual_memory allocate;
  nt_free_virtual_memory free;
  nt_write_virtual_memory write;

  HANDLE process{};

 public:
  c_injector() {
    HMODULE module = LoadLibrary("ntdll.dll");
    if (module == nullptr) throw std::runtime_error("ntdll.dll");

    open = reinterpret_cast<nt_open_process>(
        GetProcAddress(module, "NtOpenProcess"));
    if (open == nullptr) throw std::runtime_error("NtOpenProcess");

    close = reinterpret_cast<nt_close>(GetProcAddress(module, "NtClose"));
    if (close == nullptr) throw std::runtime_error("NtClose");

    allocate = reinterpret_cast<nt_allocate_virtual_memory>(
        GetProcAddress(module, "NtAllocateVirtualMemory"));
    if (allocate == nullptr)
      throw std::runtime_error("NtAllocateVirtualMemory");

    free = reinterpret_cast<nt_free_virtual_memory>(
        GetProcAddress(module, "NtFreeVirtualMemory"));
    if (free == nullptr) throw std::runtime_error("NtFreeVirtualMemory");

    write = reinterpret_cast<nt_write_virtual_memory>(
        GetProcAddress(module, "NtWriteVirtualMemory"));
    if (write == nullptr) throw std::runtime_error("NtWriteVirtualMemory");
  }

  bool set_process(std::string process) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    Process32First(snapshot, &entry);
    do {
      if (!process.compare(entry.szExeFile)) {
        CLIENT_ID client_id{reinterpret_cast<HANDLE>(entry.th32ProcessID), 0};
        OBJECT_ATTRIBUTES object_attributes;
        InitializeObjectAttributes(&object_attributes, 0, 0, 0, 0);
        open(&this->process, PROCESS_ALL_ACCESS, &object_attributes,
             &client_id);
      }
    } while (Process32Next(snapshot, &entry));
    CloseHandle(snapshot);

    return this->process != 0;
  }

  void inject(std::string path) {
    if (!process) throw c_inject_error("Process not found");

    void *address = nullptr;
    unsigned long size = path.size();

    NTSTATUS status = allocate(process, &address, 0, &size,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != STATUS_SUCCESS) throw c_inject_error(status);

    status = write(process, address, &path[0], size, 0);
    if (status != STATUS_SUCCESS) throw c_inject_error(status);

    FARPROC lla = GetProcAddress(LoadLibrary("kernel32.dll"), "LoadLibraryA");
    if (lla == nullptr) throw c_inject_error("LoadLibraryA not found");

    HANDLE thread = CreateRemoteThread(
        process, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lla), address,
        0, 0);
    if (!thread) throw c_inject_error("Failed to call thread");

    WaitForSingleObject(thread, INFINITE);
    close(thread);
    free(process, &address, &size, MEM_RELEASE);
  }
};