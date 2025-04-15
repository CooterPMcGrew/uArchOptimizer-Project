#include <iostream>
#include <chrono>

int main() {
    constexpr int N = 512;
    float sum = 0.0f;

    auto start = std::chrono::high_resolution_clock::now();

    // Perform a large number of MAC operations
    for (int i = 0; i < N * N; ++i) {
        float a = static_cast<float>(i) * 0.5f;
        float b = static_cast<float>(i) * 1.5f;
        sum += a * b;
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    std::cout << "MAC result: " << sum << "\n";
    std::cout << "Execution time: " << elapsed.count() << " seconds\n";

    return 0;
}
