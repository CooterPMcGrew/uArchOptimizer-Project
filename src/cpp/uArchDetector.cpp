#include <iostream>
#include "cpu_utils.h"
#include "microarch_mapper.h"

int main()
{
    std::wstring brand = GetCPUBrand();
    std::wstring microarch = MapBrandToMicroarchitecture(brand);

    std::wcout << L"Detected CPU: " << brand << std::endl;
    std::wcout << L"Microarchitecture: " << microarch << std::endl;

    return 0;
}
