#pragma once

#include <string>
#include <windows.h>
#include <tlhelp32.h>

#include "ntdef.hpp"
#include "pe_file.hpp"

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
    if (free == nullptr)
      throw std::runtime_error("NtFreeVirtualMemory");

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

  bool inject(std::string path) {
    void *address = nullptr;
    unsigned long size = path.size();

    NTSTATUS status = allocate(process, &address, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    //std::cout << "allocate\n";
    if (status != STATUS_SUCCESS) return false;

    status = write(process, address, &path[0], size, 0);
    //std::cout << "write\n";
    if (status != STATUS_SUCCESS) return false;

    FARPROC lla =
        GetProcAddress(LoadLibrary("kernel32.dll"), "LoadLibraryA");
    //std::cout << "lla\n";
    if (lla == nullptr) return false;

    HANDLE thread = CreateRemoteThread(process, 0, 0,
                       reinterpret_cast<LPTHREAD_START_ROUTINE>(lla), address,
                       0, 0);
    //std::cout << "thread\n";
    if (!thread) return false;

    WaitForSingleObject(thread, INFINITE);
    close(thread);
    free(process, &address, &size, MEM_RELEASE);

    return true;
  }
};