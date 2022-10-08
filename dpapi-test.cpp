#include <Windows.h>
#include "ntnative.h"
#define _NTDEF_
#include <NTSecAPI.h>

#include <cstdio>
#include <cstdlib>
#include <tchar.h>

namespace ntdll
{
    static NtClose_t NtClose = nullptr;
    static NtDeviceIoControlFile_t NtDeviceIoControlFile = nullptr;
    static NtOpenFile_t NtOpenFile = nullptr;
    static RtlInitUnicodeString_t RtlInitUnicodeString = nullptr;
    static RtlNtStatusToDosError_t RtlNtStatusToDosError = nullptr;

    static inline bool GetNtDllFunctions()
    {
        HMODULE hNtDll = ::GetModuleHandle(_T("ntdll.dll"));
        if (hNtDll)
        {
            ntdll::NtClose = NTNATIVE_GETFUNC(hNtDll, NtClose);
            ntdll::NtDeviceIoControlFile = NTNATIVE_GETFUNC(hNtDll, NtDeviceIoControlFile);
            ntdll::NtOpenFile = NTNATIVE_GETFUNC(hNtDll, NtOpenFile);
            ntdll::RtlInitUnicodeString = NTNATIVE_GETFUNC(hNtDll, RtlInitUnicodeString);
            ntdll::RtlNtStatusToDosError = NTNATIVE_GETFUNC(hNtDll, RtlNtStatusToDosError);
        }
        return (ntdll::NtClose && ntdll::NtDeviceIoControlFile && ntdll::NtOpenFile && ntdll::RtlInitUnicodeString && ntdll::RtlNtStatusToDosError);
    }
} // namespace ntdll

namespace cryptbase // also seemingly advapi32
{
    inline namespace ksecdd
    {
        constexpr ULONG IOCTL_KSEC_ENCRYPT_MEMORY_CROSS_PROC = CTL_CODE(FILE_DEVICE_KSEC, 0x05, METHOD_OUT_DIRECT, FILE_ANY_ACCESS); // 0x390016
        constexpr ULONG IOCTL_KSEC_DECRYPT_MEMORY_CROSS_PROC = CTL_CODE(FILE_DEVICE_KSEC, 0x06, METHOD_OUT_DIRECT, FILE_ANY_ACCESS); // 0x39001a
        constexpr ULONG IOCTL_KSEC_ENCRYPT_MEMORY_SAME_LOGON = CTL_CODE(FILE_DEVICE_KSEC, 0x07, METHOD_OUT_DIRECT, FILE_ANY_ACCESS); // 0x39001e
        constexpr ULONG IOCTL_KSEC_DECRYPT_MEMORY_SAME_LOGON = CTL_CODE(FILE_DEVICE_KSEC, 0x08, METHOD_OUT_DIRECT, FILE_ANY_ACCESS); // 0x390022
        constexpr ULONG IOCTL_KSEC_ENCRYPT_MEMORY = CTL_CODE(FILE_DEVICE_KSEC, 0x03, METHOD_OUT_DIRECT, FILE_ANY_ACCESS);            // 0x39000e
        constexpr ULONG IOCTL_KSEC_DECRYPT_MEMORY = CTL_CODE(FILE_DEVICE_KSEC, 0x04, METHOD_OUT_DIRECT, FILE_ANY_ACCESS);            // 0x390012
        constexpr ULONG IOCTL_KSEC_DECRYPT_SAME_LOGON = IOCTL_KSEC_DECRYPT_MEMORY_SAME_LOGON;
        constexpr ULONG IOCTL_KSEC_ENCRYPT_SAME_LOGON = IOCTL_KSEC_ENCRYPT_MEMORY_SAME_LOGON;
        constexpr ULONG IOCTL_KSEC_DECRYPT_SAME_PROCESS = IOCTL_KSEC_DECRYPT_MEMORY;
        constexpr ULONG IOCTL_KSEC_ENCRYPT_SAME_PROCESS = IOCTL_KSEC_ENCRYPT_MEMORY;
        constexpr ULONG IOCTL_KSEC_DECRYPT_CROSS_PROCESS = IOCTL_KSEC_DECRYPT_MEMORY_CROSS_PROC;
        constexpr ULONG IOCTL_KSEC_ENCRYPT_CROSS_PROCESS = IOCTL_KSEC_ENCRYPT_MEMORY_CROSS_PROC;
        constexpr ULONG IOCTL_KSEC_ENCRYPT_FOR_SYSTEM = CTL_CODE(FILE_DEVICE_KSEC, 0x1e, METHOD_OUT_DIRECT, FILE_ANY_ACCESS); // 0x39007A
        constexpr ULONG IOCTL_KSEC_DECRYPT_FOR_SYSTEM = CTL_CODE(FILE_DEVICE_KSEC, 0x1f, METHOD_OUT_DIRECT, FILE_ANY_ACCESS); // 0x39007E

        static HANDLE g_hKsecDD = nullptr; // yeah, it's that in cryptbase.dll, not INVALID_HANDLE_VALUE
    }                                      // namespace ksecdd

    // This lives internally in cryptbase.dll and gets called from the exported function CryptBaseInitialize, which is its DllEntryPoint
    EXTERN_C BOOL WINAPI EncryptMemoryInitialize()
    {
        using ntdll::NtClose;
        using ntdll::NtOpenFile;
        using ntdll::RtlInitUnicodeString;

        UNICODE_STRING usDeviceName{};
        IO_STATUS_BLOCK iostat{};
        OBJECT_ATTRIBUTES oa{};
        HANDLE hKsecDD = nullptr;

        RtlInitUnicodeString(&usDeviceName, L"\\Device\\KsecDD");
        InitializeObjectAttributes(&oa, &usDeviceName, 0, nullptr, nullptr);

        if (!NT_SUCCESS(NtOpenFile(
                &hKsecDD, FILE_READ_ACCESS | SYNCHRONIZE, &oa, &iostat, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT)))
        {
            return FALSE;
        }
        if (InterlockedCompareExchangePointer(&g_hKsecDD, hKsecDD, nullptr))
        {
            NtClose(hKsecDD);
        }
        return TRUE;
    }

    using ntdll::NtDeviceIoControlFile;

    // This function is known as cryptbase!SystemFunction040 and gets called by dpapi!CryptProtectMemory
    // xref: https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtlencryptmemory
    EXTERN_C NTSTATUS WINAPI RtlEncryptMemory(_Inout_updates_bytes_(MemorySize) PVOID Memory, _In_ ULONG MemorySize, _In_ ULONG OptionFlags)
    {
        HANDLE hKsecDD = nullptr;
        ULONG ioctl = 0;

        hKsecDD = g_hKsecDD;
        if (!g_hKsecDD)
        {
            if (!EncryptMemoryInitialize())
            {
                return STATUS_UNSUCCESSFUL;
            }
            hKsecDD = g_hKsecDD;
        }
        switch (OptionFlags) // seems more like a bit mask of mutually exclusive bits, no?!
        {
        case 0:
            ioctl = IOCTL_KSEC_ENCRYPT_SAME_PROCESS;
            break;
        case RTL_ENCRYPT_OPTION_CROSS_PROCESS:
            ioctl = IOCTL_KSEC_ENCRYPT_CROSS_PROCESS;
            break;
        case RTL_ENCRYPT_OPTION_SAME_LOGON:
            ioctl = IOCTL_KSEC_ENCRYPT_SAME_LOGON;
            break;
        case RTL_ENCRYPT_OPTION_FOR_SYSTEM:
            ioctl = IOCTL_KSEC_ENCRYPT_FOR_SYSTEM;
            break;
        default:
            return STATUS_INVALID_PARAMETER;
        }
        IO_STATUS_BLOCK iostat{};
        return NtDeviceIoControlFile(hKsecDD, nullptr, nullptr, nullptr, &iostat, ioctl, Memory, MemorySize, Memory, MemorySize);
    }

    // This function is known as cryptbase!SystemFunction041 and gets called by dpapi!CryptUnprotectMemory
    // xref: https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtldecryptmemory
    EXTERN_C NTSTATUS __stdcall RtlDecryptMemory(_Inout_updates_bytes_(MemorySize) PVOID Memory, _In_ ULONG MemorySize, _In_ ULONG OptionFlags)
    {
        HANDLE hKsecDD = nullptr;
        ULONG ioctl = 0;

        hKsecDD = g_hKsecDD;
        if (!g_hKsecDD)
        {
            if (!EncryptMemoryInitialize())
            {
                return STATUS_UNSUCCESSFUL;
            }
            hKsecDD = g_hKsecDD;
        }

        switch (OptionFlags) // seems more like a bit mask of mutually exclusive bits, no?!
        {
        case 0:
            ioctl = IOCTL_KSEC_DECRYPT_SAME_PROCESS;
            break;
        case RTL_ENCRYPT_OPTION_CROSS_PROCESS:
            ioctl = IOCTL_KSEC_DECRYPT_CROSS_PROCESS;
            break;
        case RTL_ENCRYPT_OPTION_SAME_LOGON:
            ioctl = IOCTL_KSEC_DECRYPT_SAME_LOGON;
            break;
        case RTL_ENCRYPT_OPTION_FOR_SYSTEM:
            ioctl = IOCTL_KSEC_DECRYPT_FOR_SYSTEM;
            break;
        default:
            return STATUS_INVALID_PARAMETER;
        }

        IO_STATUS_BLOCK iostat{};
        return NtDeviceIoControlFile(hKsecDD, nullptr, nullptr, nullptr, &iostat, ioctl, Memory, MemorySize, Memory, MemorySize);
    }
} // namespace cryptbase

namespace dpapi
{
    using ntdll::RtlNtStatusToDosError;

    BOOL WINAPI CryptProtectMemory(_Inout_ LPVOID pDataIn, _In_ DWORD cbDataIn, _In_ DWORD dwFlags)
    {
        NTSTATUS Status = cryptbase::RtlEncryptMemory(pDataIn, cbDataIn, dwFlags);
        if (NT_SUCCESS(Status))
        {
            return TRUE;
        }
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    BOOL WINAPI CryptUnprotectMemory(_Inout_ LPVOID pDataIn, _In_ DWORD cbDataIn, _In_ DWORD dwFlags)
    {
        NTSTATUS Status = cryptbase::RtlDecryptMemory(pDataIn, cbDataIn, dwFlags);
        if (NT_SUCCESS(Status))
        {
            return TRUE;
        }
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }
} // namespace dpapi

int _tmain()
{
    if (!ntdll::GetNtDllFunctions())
    {
        _tprintf(_T("FATAL: could not retrieve all required function pointers from ntdll.dll\n"));
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
