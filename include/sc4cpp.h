/**
 * Copyright (c) 2021 smh <windpiaoxue@foxmail.com>
 * All rights reserved
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#pragma once

#if !defined(__clang__) || !defined(_WIN32)
#error "sc4cpp only supports Clang on windows"
#endif

#include <ntddk.h>
#include <stdint.h>
#include <minwindef.h>
#include <ntimage.h>
#define _countof(array) (sizeof(array) / sizeof(array[0]))
#define _T(x) L##x
// #include <type_traits>

// #include <utility>

#ifdef _DEBUG
#define SC_DEBUG
#endif // _DEBUG

#ifdef _WIN64
#define SC_WIN64
#endif // _WIN64

#define SC_CONSTEXPR constexpr
#define SC_NOINLINE __declspec(noinline)
#define SC_FORCEINLINE __forceinline

#define SC_EXTERN_C_BEGIN                                                      \
    extern "C"                                                                 \
    {
#define SC_DLL_IMPORT __declspec(dllimport)
#define SC_DLL_EXPORT __declspec(dllexport)
#define SC_EXTERN_C_END }

#define SC_NAKEDFUNC __declspec(naked)
#define SC_ASM __asm
#define SC_EMIT(c) __asm _emit(c)

#define SC_CODESEG(s) __declspec(code_seg(".code$" #s))

#define SC_CODESEG_START SC_CODESEG(CAA)
#define SC_CODESEG_END SC_CODESEG(CZZ)
#define SC_CODESEG_MAIN SC_CODESEG(CBA)

// Make sure it is between MAIN and END.
#define SC_CODESEG_REORDERING SC_CODESEG(CXI)

namespace SC
{
// https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
template <typename Converter>
SC_FORCEINLINE SC_CONSTEXPR DWORD Hash(PCSTR lpName)
{
    DWORD dwHash = 2166136261u;
    for (; *lpName != '\0'; ++lpName)
    {
        dwHash = (dwHash ^ (BYTE)Converter()(*lpName)) * 16777619ull;
    }
    return dwHash;
}
SC_FORCEINLINE SC_CONSTEXPR DWORD Hash(PCSTR lpName)
{
    struct Converter
    {
        SC_CONSTEXPR Converter() {}
        SC_CONSTEXPR CHAR operator()(CHAR c) const { return c; }
    };
    return Hash<Converter>(lpName);
}
SC_FORCEINLINE SC_CONSTEXPR DWORD HashI(PCSTR lpName)
{
    struct Converter
    {
        SC_CONSTEXPR Converter() {}
        SC_CONSTEXPR CHAR operator()(CHAR c) const
        {
            return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
        }
    };
    return Hash<Converter>(lpName);
}

SC_FORCEINLINE PVOID GetNtoskrnlBaseAddress()
{
#pragma pack(push, 1)
    typedef struct
    {
        UCHAR Padding[4];
        PVOID InterruptServiceRoutine;
    } IDT_ENTRY;
#pragma pack(pop)

    // Find the address of IdtBase using gs register.
    const auto idt_base = reinterpret_cast<IDT_ENTRY *>(__readgsqword(0x38));

    // Find the address of the first (or any) interrupt service routine.
    const auto first_isr_address = idt_base[0].InterruptServiceRoutine;

    // search this pattern "48 8D 1D ?? ?? ?? FF" backwards from the
    // first_isr_address
    auto ptr = reinterpret_cast<uintptr_t>(first_isr_address);
    while (1)
    {
        if (*(reinterpret_cast<uint8_t *>(ptr)) != 0x48 ||
            *(reinterpret_cast<uint8_t *>(ptr + 1)) != 0x8D ||
            *(reinterpret_cast<uint8_t *>(ptr + 2)) != 0x1D ||
            *(reinterpret_cast<uint8_t *>(ptr + 6)) != 0xFF)
        {
            ptr--;
        }
        else
        {
            // we found the pattern, now we need to calculate the offset
            auto offset = *(reinterpret_cast<int32_t *>(ptr + 3));
            auto ntoskernl_base = ptr + 7 + offset;
            // check ntoskernel_base is page aligned
            if (ntoskernl_base % 0x1000 == 0)
            {
                return reinterpret_cast<void *>(ntoskernl_base);
            }
            else
            {
                ptr--;
            }
        }
    }
}

SC_FORCEINLINE PIMAGE_NT_HEADERS GetNTHeaders(PVOID lpDLLBase)
{
    PIMAGE_DOS_HEADER lpDOSHeader = (PIMAGE_DOS_HEADER)lpDLLBase;
    return (PIMAGE_NT_HEADERS)((PBYTE)lpDLLBase + lpDOSHeader->e_lfanew);
}
SC_FORCEINLINE PVOID MmGetSystemRoutineAddressByHash(DWORD dwProcHash)
{
    auto lpNtBase = (PSTR)GetNtoskrnlBaseAddress();
    PIMAGE_NT_HEADERS lpNTHeaders = GetNTHeaders(lpNtBase);
    DWORD dwExportDirectoryRAV =
        lpNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
            .VirtualAddress;
    if (dwExportDirectoryRAV == 0)
    {
    }
    PIMAGE_EXPORT_DIRECTORY lpExportDirectory =
        (PIMAGE_EXPORT_DIRECTORY)(lpNtBase + dwExportDirectoryRAV);
    PDWORD lpNameRAVs = (PDWORD)(lpNtBase + lpExportDirectory->AddressOfNames);
    PWORD lpOrdinals =
        (PWORD)(lpNtBase + lpExportDirectory->AddressOfNameOrdinals);
    PDWORD lpProcRAVs =
        (PDWORD)(lpNtBase + lpExportDirectory->AddressOfFunctions);
    for (DWORD dwIdx = 0; dwIdx < lpExportDirectory->NumberOfNames; ++dwIdx)
    {
        if (Hash(lpNtBase + lpNameRAVs[dwIdx]) == dwProcHash)
        {
            return lpNtBase + lpProcRAVs[lpOrdinals[dwIdx]];
        }
    }
    __debugbreak();
    return NULL; // No return
}
// For Compile-time calculation
template <DWORD dwProcHash>
SC_FORCEINLINE PVOID MmGetSystemRoutineAddressByHash()
{
    return MmGetSystemRoutineAddressByHash(dwProcHash);
}

SC_FORCEINLINE PVOID GetProcAddressByHash(DWORD dwDLLHash, DWORD dwProcHash)
{
    __debugbreak();
    LPSTR lpDLLBase = (LPSTR) nullptr;
    if (lpDLLBase == NULL)
    {
    }
    PIMAGE_NT_HEADERS lpNTHeaders = GetNTHeaders(lpDLLBase);
    DWORD dwExportDirectoryRAV =
        lpNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
            .VirtualAddress;
    if (dwExportDirectoryRAV == 0)
    {
    }
    PIMAGE_EXPORT_DIRECTORY lpExportDirectory =
        (PIMAGE_EXPORT_DIRECTORY)(lpDLLBase + dwExportDirectoryRAV);
    if (HashI(lpDLLBase + lpExportDirectory->Name) != dwDLLHash)
    {
    }
    PDWORD lpNameRAVs = (PDWORD)(lpDLLBase + lpExportDirectory->AddressOfNames);
    PWORD lpOrdinals =
        (PWORD)(lpDLLBase + lpExportDirectory->AddressOfNameOrdinals);
    PDWORD lpProcRAVs =
        (PDWORD)(lpDLLBase + lpExportDirectory->AddressOfFunctions);
    for (DWORD dwIdx = 0; dwIdx < lpExportDirectory->NumberOfNames; ++dwIdx)
    {
        if (Hash(lpDLLBase + lpNameRAVs[dwIdx]) == dwProcHash)
        {
            // FIXME: DLL Function Forwarding
            return lpDLLBase + lpProcRAVs[lpOrdinals[dwIdx]];
        }
    }
    __debugbreak();
    return NULL; // No return
}

// For Compile-time calculation
template <DWORD dwDLLHash, DWORD dwProcHash>
SC_FORCEINLINE PVOID GetProcAddressByHash()
{
    return GetProcAddressByHash(dwDLLHash, dwProcHash);
}

template <class _Ty, _Ty... _Vals> struct integer_sequence
{ // sequence of integer parameters

    using value_type = _Ty;

    _NODISCARD static constexpr size_t size() noexcept
    {
        return sizeof...(_Vals);
    }
};
// ALIAS TEMPLATE make_integer_sequence
template <class _Ty, _Ty _Size>
using make_integer_sequence = __make_integer_seq<integer_sequence, _Ty, _Size>;

template <size_t... _Vals>
using index_sequence = integer_sequence<size_t, _Vals...>;

template <size_t _Size>
using make_index_sequence = make_integer_sequence<size_t, _Size>;

template <class... _Types>
using index_sequence_for = make_index_sequence<sizeof...(_Types)>;

// Position Independent String
template <typename CharType, typename Indices> struct PIString;
template <typename CharType, size_t... Indices>
struct PIString<CharType, index_sequence<Indices...>>
{
    CharType szBuffer_[sizeof...(Indices)];
    SC_FORCEINLINE SC_CONSTEXPR explicit PIString(
        const CharType (&szLiteral)[sizeof...(Indices)])
        : szBuffer_{(szLiteral[Indices])...}
    {
    }
};
} // namespace SC

#ifdef SC_WIN64
#define SC_BEGIN_CODE                                                          \
    SC_DLL_EXPORT SC_CODESEG_START VOID SCBegin() { SCMain(NULL); }
#else
// clang-format off
#define SC_BEGIN_CODE                                                                              \
    SC_DLL_EXPORT SC_CODESEG_START SC_NAKEDFUNC VOID SCBegin() {                                   \
        /* CALL $+5 */                                                                             \
        SC_EMIT(0xE8) SC_EMIT(0x00) SC_EMIT(0x00) SC_EMIT(0x00) SC_EMIT(0x00)                      \
        SC_ASM POP EAX                                                                             \
        SC_ASM LEA EAX, [EAX - 5]                                                                  \
        SC_ASM LEA ECX, [SCBegin]                                                                  \
        SC_ASM NEG ECX                                                                             \
        SC_ASM LEA EAX, [EAX + ECX + SCMain]                                                       \
        SC_ASM PUSH EAX                                                                            \
        SC_ASM CALL EAX                                                                            \
        SC_ASM RET                                                                                 \
    }
// clang-format on
#endif // SC_WIN64

#define SC_MAIN_BEGIN()                                                        \
    SC_EXTERN_C_BEGIN                                                          \
    SC_DLL_EXPORT VOID WINAPI SCMain(ULONG_PTR SCMainVA);                      \
    SC_BEGIN_CODE                                                              \
    SC_DLL_EXPORT SC_CODESEG_MAIN VOID WINAPI SCMain(ULONG_PTR SCMainVA)
#define SC_MAIN_END()                                                          \
    SC_DLL_EXPORT SC_CODESEG_END VOID SCEnd() { __debugbreak(); }              \
    SC_EXTERN_C_END

#define SC_PISTRINGA(szLiteralA)                                               \
    (::SC::PIString<CHAR, ::SC::make_index_sequence<_countof(szLiteralA)>>(          \
         szLiteralA)                                                           \
         .szBuffer_)
#define SC_PISTRINGW(szLiteralW)                                               \
    (::SC::PIString<WCHAR, ::SC::make_index_sequence<_countof(szLiteralW)>>(         \
         szLiteralW)                                                           \
         .szBuffer_)
#define SC_PISTRINGU(szLiteralW)                                               \
    (&UNICODE_STRING{sizeof(szLiteralW) - sizeof(WCHAR), sizeof(szLiteralW),   \
                     SC_PISTRINGW(szLiteralW)})

#ifdef SC_WIN64
#define SC_PIFUNCTION(fnReordered) ((decltype(fnReordered) *)fnReordered)
#else
// Must be invoked in SCMain.
#define SC_PIFUNCTION(fnReordered)                                             \
    ((decltype(fnReordered) *)(((ULONG_PTR)(fnReordered) -                     \
                                (ULONG_PTR)SCMain) +                           \
                               SCMainVA))
#endif // SC_WIN64

#define SC_GET_API_ADDRESS(szAPIName)                                          \
    (::SC::MmGetSystemRoutineAddressByHash<::SC::Hash(szAPIName)>())

// #define SC_IMPORT_API_AS(fnVarName, szDLLName, fnAPIName)                      \
//     auto fnVarName =                                                           \
//         (decltype(::fnAPIName) *)SC_GET_API_ADDRESS(szDLLName, #fnAPIName)
// #define SC_IMPORT_API(szDLLName, fnAPIName)                                    \
//     SC_IMPORT_API_AS(fnAPIName, szDLLName, fnAPIName)
#define SC_IMPORT_API_AS(fnVarName, fnAPIName)                                 \
    auto fnVarName = (decltype(::fnAPIName) *)SC_GET_API_ADDRESS(#fnAPIName)
#define SC_IMPORT_API(fnAPIName) SC_IMPORT_API_AS(fnAPIName, fnAPIName)

#define SC_IMPORT_API_BATCH_BEGIN()                                            \
    SC_IMPORT_API_AS(fnSCGetFnAddress, MmGetSystemRoutineAddress)
#define SC_IMPORT_API_BATCH(fnAPIName)                                         \
    auto fnAPIName =                                                           \
        (decltype(::fnAPIName) *)(fnSCGetFnAddress(SC_PISTRINGU(_T(#fnAPIName))))
#define SC_IMPORT_API_BATCH_END()
