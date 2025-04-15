#include "cpu_utils.h"
#include <windows.h>
#include <intrin.h>
#include <string>   // <--- Required for std::wstring
#include <cstring>

std::wstring GetCPUBrand()
{
    int cpuInfo[4] = { -1 };
    char brandRaw[49] = {}; // 48 chars + null terminator

    // CPUID calls to get brand string in pieces
    __cpuid(cpuInfo, 0x80000002);
    memcpy(brandRaw, cpuInfo, sizeof(cpuInfo));

    __cpuid(cpuInfo, 0x80000003);
    memcpy(brandRaw + 16, cpuInfo, sizeof(cpuInfo));

    __cpuid(cpuInfo, 0x80000004);
    memcpy(brandRaw + 32, cpuInfo, sizeof(cpuInfo));

    // Convert char* (UTF-8/ASCII) to wide string
    int len = MultiByteToWideChar(CP_ACP, 0, brandRaw, -1, NULL, 0);
    std::wstring brand(len, L'\0');
    MultiByteToWideChar(CP_ACP, 0, brandRaw, -1, &brand[0], len);

    return brand;
}