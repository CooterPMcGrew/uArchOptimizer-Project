#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <cmath>
#include <random>
#include <algorithm>
#include <iomanip>

// Define different benchmark types to test various architectural optimizations
enum class BenchmarkType {
    SCALAR_COMPUTE,       // FP/Integer arithmetic operations
    VECTOR_COMPUTE,       // SIMD operations
    BRANCH_PREDICTION,    // Tests branch prediction efficiency
    MEMORY_ACCESS,        // Tests cache efficiency
    COMBINED              // Combined workload
};

// Forward declarations
double run_scalar_benchmark(int iterations, bool optimize);
double run_vector_benchmark(int iterations, bool optimize);
double run_branch_benchmark(int iterations, bool optimize);
double run_memory_benchmark(int iterations, bool optimize);
double run_combined_benchmark(int iterations, bool optimize);

int main(int argc, char* argv[]) {
    // Default parameters
    BenchmarkType benchType = BenchmarkType::COMBINED;
    int iterations = 10000000;
    bool optimize = false;
    
    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--scalar") {
            benchType = BenchmarkType::SCALAR_COMPUTE;
        } else if (arg == "--vector") {
            benchType = BenchmarkType::VECTOR_COMPUTE;
        } else if (arg == "--branch") {
            benchType = BenchmarkType::BRANCH_PREDICTION;
        } else if (arg == "--memory") {
            benchType = BenchmarkType::MEMORY_ACCESS;
        } else if (arg == "--combined") {
            benchType = BenchmarkType::COMBINED;
        } else if (arg == "--optimize" || arg == "-O") {
            optimize = true;
        } else if (arg == "--iterations" || arg == "-i") {
            if (i + 1 < argc) {
                iterations = std::stoi(argv[i + 1]);
                i++;
            }
        }
    }
    
    // Print benchmark configuration
    std::cout << "uArchOptimizer Benchmark Tool" << std::endl;
    std::cout << "============================" << std::endl;
    std::cout << "Iterations: " << iterations << std::endl;
    std::cout << "Optimization: " << (optimize ? "Enabled" : "Disabled") << std::endl;
    std::cout << "Benchmark Type: ";
    
    double elapsedTime = 0.0;
    
    // Run the selected benchmark
    switch (benchType) {
        case BenchmarkType::SCALAR_COMPUTE:
            std::cout << "Scalar Compute" << std::endl;
            elapsedTime = run_scalar_benchmark(iterations, optimize);
            break;
            
        case BenchmarkType::VECTOR_COMPUTE:
            std::cout << "Vector Compute" << std::endl;
            elapsedTime = run_vector_benchmark(iterations, optimize);
            break;
            
        case BenchmarkType::BRANCH_PREDICTION:
            std::cout << "Branch Prediction" << std::endl;
            elapsedTime = run_branch_benchmark(iterations, optimize);
            break;
            
        case BenchmarkType::MEMORY_ACCESS:
            std::cout << "Memory Access" << std::endl;
            elapsedTime = run_memory_benchmark(iterations, optimize);
            break;
            
        case BenchmarkType::COMBINED:
            std::cout << "Combined Workload" << std::endl;
            elapsedTime = run_combined_benchmark(iterations, optimize);
            break;
    }
    
    // Print results
    std::cout << "============================" << std::endl;
    std::cout << "Execution time: " << std::fixed << std::setprecision(6) << elapsedTime << " seconds" << std::endl;
    std::cout << "Operations/sec: " << std::fixed << std::setprecision(2) 
              << static_cast<double>(iterations) / elapsedTime << std::endl;
    
    return 0;
}

// Scalar compute benchmark (similar to your original MAC benchmark)
double run_scalar_benchmark(int iterations, bool optimize) {
    double sum = 0.0;
    
    // For non-optimized version, we add unpredictable operations
    std::vector<double> values;
    if (!optimize) {
        // Create some semi-random values to hamper compiler optimizations
        values.resize(iterations);
        for (int i = 0; i < iterations; ++i) {
            values[i] = std::sin(static_cast<double>(i) * 0.01);
        }
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Optimized path does straightforward computations
    if (optimize) {
        for (int i = 0; i < iterations; ++i) {
            double a = static_cast<double>(i) * 0.5;
            double b = static_cast<double>(i) * 1.5;
            sum += a * b; // MAC operation
        }
    } 
    // Non-optimized path has more complex calculations
    else {
        for (int i = 0; i < iterations; ++i) {
            double a = std::sqrt(static_cast<double>(i) * 0.5);
            double b = std::log(static_cast<double>(i) + 1.0) * 1.5;
            sum += a * b * values[i % values.size()]; // More complex MAC with memory access
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    
    // Prevent compiler from optimizing away the calculation
    std::cout << "Result checksum: " << sum << std::endl;
    
    return elapsed.count();
}

// Vector compute benchmark (tests SIMD optimization)
double run_vector_benchmark(int iterations, bool optimize) {
    const int VECTOR_SIZE = 1024;
    std::vector<float> vec1(VECTOR_SIZE);
    std::vector<float> vec2(VECTOR_SIZE);
    std::vector<float> result(VECTOR_SIZE);
    
    // Initialize vectors
    for (int i = 0; i < VECTOR_SIZE; ++i) {
        vec1[i] = static_cast<float>(i) * 0.01f;
        vec2[i] = static_cast<float>(i) * 0.02f;
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // In optimized mode, the compiler has a better chance to vectorize this loop
    if (optimize) {
        for (int iter = 0; iter < iterations / VECTOR_SIZE; ++iter) {
            for (int i = 0; i < VECTOR_SIZE; ++i) {
                result[i] = vec1[i] * vec2[i] + vec1[i];
            }
        }
    } 
    // In non-optimized mode, the use of conditional makes vectorization harder
    else {
        for (int iter = 0; iter < iterations / VECTOR_SIZE; ++iter) {
            for (int i = 0; i < VECTOR_SIZE; ++i) {
                if (i % 2 == 0) {
                    result[i] = vec1[i] * vec2[i] + vec1[i];
                } else {
                    result[i] = vec1[i] * vec2[i] - vec1[i];
                }
            }
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    
    // Prevent compiler from optimizing away the calculation
    float checksum = 0.0f;
    for (int i = 0; i < VECTOR_SIZE; ++i) {
        checksum += result[i];
    }
    std::cout << "Result checksum: " << checksum << std::endl;
    
    return elapsed.count();
}

// Branch prediction benchmark
double run_branch_benchmark(int iterations, bool optimize) {
    std::vector<int> data(iterations);
    
    // Generate data with different patterns based on optimization flag
    if (optimize) {
        // Sorted data is easier for branch prediction
        for (int i = 0; i < iterations; ++i) {
            data[i] = i % 100;
        }
    } else {
        // Random data causes more branch mispredictions
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(0, 100);
        
        for (int i = 0; i < iterations; ++i) {
            data[i] = distrib(gen);
        }
        
        // Shuffle to ensure randomness
        std::shuffle(data.begin(), data.end(), gen);
    }
    
    int sum = 0;
    auto start = std::chrono::high_resolution_clock::now();
    
    // Simple branch-heavy loop
    for (int i = 0; i < iterations; ++i) {
        if (data[i] > 50) {
            sum += data[i];
        } else {
            sum -= data[i];
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    
    std::cout << "Result checksum: " << sum << std::endl;
    
    return elapsed.count();
}

// Memory access benchmark
double run_memory_benchmark(int iterations, bool optimize) {
    const int ARRAY_SIZE = 10000000; // 10M elements
    std::vector<int> data(ARRAY_SIZE);
    
    // Initialize array
    for (int i = 0; i < ARRAY_SIZE; ++i) {
        data[i] = i;
    }
    
    std::vector<int> indices(iterations);
    
    // Generate access patterns
    if (optimize) {
        // Sequential access (good for cache)
        for (int i = 0; i < iterations; ++i) {
            indices[i] = i % ARRAY_SIZE;
        }
    } else {
        // Random access (cache misses)
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(0, ARRAY_SIZE - 1);
        
        for (int i = 0; i < iterations; ++i) {
            indices[i] = distrib(gen);
        }
    }
    
    int sum = 0;
    auto start = std::chrono::high_resolution_clock::now();
    
    // Access memory using the pattern
    for (int i = 0; i < iterations; ++i) {
        sum += data[indices[i]];
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    
    std::cout << "Result checksum: " << sum << std::endl;
    
    return elapsed.count();
}

// Combined benchmark
double run_combined_benchmark(int iterations, bool optimize) {
    // Run a bit of each benchmark
    int subIterations = iterations / 4;
    
    double time1 = run_scalar_benchmark(subIterations, optimize);
    double time2 = run_vector_benchmark(subIterations, optimize);
    double time3 = run_branch_benchmark(subIterations, optimize);
    double time4 = run_memory_benchmark(subIterations, optimize);
    
    std::cout << "Individual timings:" << std::endl;
    std::cout << "- Scalar: " << time1 << " seconds" << std::endl;
    std::cout << "- Vector: " << time2 << " seconds" << std::endl;
    std::cout << "- Branch: " << time3 << " seconds" << std::endl;
    std::cout << "- Memory: " << time4 << " seconds" << std::endl;
    
    return time1 + time2 + time3 + time4;
}