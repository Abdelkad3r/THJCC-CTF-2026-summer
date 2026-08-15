#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using Password = std::array<uint8_t, 14>;

constexpr uint64_t MASK40 = (1ULL << 40) - 1;
constexpr uint64_t SPACE = 78364164096ULL;  // 6^14
constexpr uint32_t CHAIN_LEN = 24576;
constexpr uint32_t NUM_CHAINS = SPACE / CHAIN_LEN;
constexpr uint32_t END_VALUES = 1679616;    // 6^8
constexpr uint32_t END_BITS = 21;
constexpr uint64_t RMIX1 = 0x5851f42d4c95ULL;
constexpr uint64_t RMIX2 = 0xf1357aea2e63ULL;
constexpr char CHARSET[] = "yaniko";

constexpr uint32_t K1 = 21;
constexpr uint32_t K2 = 20;
constexpr uint32_t K3 = 24;
constexpr uint32_t K4 = 108000;

uint32_t rotl32(uint32_t value, unsigned amount) {
    return (value << amount) | (value >> (32 - amount));
}

uint64_t yani40(const Password &password) {
    uint32_t a = K1 ^ 0x9E3779B9U;
    uint32_t b = K2 + 0x85EBCA6BU;
    uint32_t c = K3 ^ 0xC2B2AE35U;
    uint32_t d = K4 + 0x27D4EB2FU;

    for (uint32_t pass = 0; pass < 3; ++pass) {
        for (uint8_t digit : password) {
            uint8_t byte = static_cast<uint8_t>(CHARSET[digit]);
            a = (a ^ byte) * 0x01000193U;
            b = rotl32(b + a, 13) ^ c;
            c = (c * 5U + 0xF00DU) ^ b;
            d = rotl32(d ^ a, 7) + b;
            a += d;
        }
        a ^= pass * 0x7FEB352DU;
    }

    for (int round = 0; round < 4; ++round) {
        a = (a ^ (b >> 15)) * 0x2545F491U;
        b = (b ^ (c >> 13)) * 0x9E3779B1U;
        c = (c ^ (d >> 11)) * 0x85EBCA77U;
        d = (d ^ (a >> 16)) * 0xC2B2AE3DU;
    }

    uint64_t value = (static_cast<uint64_t>(a ^ c) << 32) | (b ^ d);
    return value & MASK40;
}

Password reduce_at(uint64_t hash, uint32_t index) {
    uint64_t value = (hash + static_cast<uint64_t>(index) * RMIX1) & MASK40;
    value = ((value << 21) | (value >> 19)) & MASK40;
    value = (value * RMIX2) & MASK40;
    value ^= value >> 23;
    value %= SPACE;

    Password password{};
    for (auto &digit : password) {
        digit = value % 6;
        value /= 6;
    }
    return password;
}

Password index_to_password(uint32_t index) {
    Password password{};
    for (auto &digit : password) {
        digit = index % 6;
        index /= 6;
    }
    return password;
}

uint32_t endpoint_value(const Password &password) {
    uint32_t value = 0;
    uint32_t place = 1;
    for (size_t index = 0; index < 8; ++index) {
        value += password[index] * place;
        place *= 6;
    }
    return value;
}

std::string password_string(const Password &password) {
    std::string result;
    result.reserve(password.size());
    for (uint8_t digit : password) {
        result.push_back(CHARSET[digit]);
    }
    return result;
}

uint64_t parse_hex40(const std::string &text) {
    return std::stoull(text, nullptr, 16) & MASK40;
}

struct TableIndex {
    std::vector<uint32_t> offsets;
    std::vector<uint32_t> chain_ids;
};

uint32_t read_packed_value(const std::vector<uint8_t> &data, uint32_t index) {
    uint64_t bit_offset = static_cast<uint64_t>(index) * END_BITS;
    size_t byte_offset = bit_offset / 8;
    unsigned shift = bit_offset % 8;
    uint64_t chunk = 0;
    for (unsigned byte = 0; byte < 4 && byte_offset + byte < data.size(); ++byte) {
        chunk |= static_cast<uint64_t>(data[byte_offset + byte]) << (8 * byte);
    }
    return (chunk >> shift) & ((1U << END_BITS) - 1);
}

TableIndex load_table(const std::string &path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Could not open " + path);
    }
    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>()
    );

    TableIndex result;
    result.offsets.assign(END_VALUES + 1, 0);
    result.chain_ids.resize(NUM_CHAINS);

    for (uint32_t chain = 0; chain < NUM_CHAINS; ++chain) {
        uint32_t value = read_packed_value(data, chain);
        ++result.offsets[value + 1];
    }
    for (uint32_t value = 1; value <= END_VALUES; ++value) {
        result.offsets[value] += result.offsets[value - 1];
    }

    std::vector<uint32_t> cursor = result.offsets;
    for (uint32_t chain = 0; chain < NUM_CHAINS; ++chain) {
        uint32_t value = read_packed_value(data, chain);
        result.chain_ids[cursor[value]++] = chain;
    }
    return result;
}

Password recover_one(uint64_t target, const TableIndex &table) {
    std::atomic<int> next_position{static_cast<int>(CHAIN_LEN) - 1};
    std::atomic<bool> found{false};
    Password answer{};
    std::mutex answer_mutex;

    unsigned workers = std::max(1U, std::thread::hardware_concurrency());
    std::vector<std::thread> threads;
    threads.reserve(workers);

    for (unsigned worker = 0; worker < workers; ++worker) {
        threads.emplace_back([&]() {
            while (!found.load(std::memory_order_relaxed)) {
                int position = next_position.fetch_sub(1);
                if (position < 0) {
                    return;
                }

                Password endpoint = reduce_at(target, position);
                bool aborted = false;
                for (uint32_t index = position + 1; index < CHAIN_LEN; ++index) {
                    endpoint = reduce_at(yani40(endpoint), index);
                    if ((index & 0xFF) == 0 && found.load(std::memory_order_relaxed)) {
                        aborted = true;
                        break;
                    }
                }
                if (aborted) {
                    return;
                }

                uint32_t value = endpoint_value(endpoint);
                for (uint32_t at = table.offsets[value]; at < table.offsets[value + 1]; ++at) {
                    Password candidate = index_to_password(table.chain_ids[at]);
                    for (int index = 0; index <= position; ++index) {
                        uint64_t hash = yani40(candidate);
                        if (hash == target) {
                            std::lock_guard<std::mutex> lock(answer_mutex);
                            if (!found.exchange(true)) {
                                answer = candidate;
                            }
                            return;
                        }
                        candidate = reduce_at(hash, index);
                        if ((index & 0xFF) == 0 && found.load(std::memory_order_relaxed)) {
                            return;
                        }
                    }
                }
            }
        });
    }

    for (auto &thread : threads) {
        thread.join();
    }
    if (!found) {
        throw std::runtime_error("No preimage was recovered");
    }
    return answer;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " nyan.tbl shadow.txt\n";
        return 2;
    }

    try {
        auto started = std::chrono::steady_clock::now();
        TableIndex table = load_table(argv[1]);
        std::cout << "indexed " << NUM_CHAINS << " chains\n";

        std::ifstream shadows(argv[2]);
        std::string line;
        while (std::getline(shadows, line)) {
            size_t separator = line.find(':');
            if (separator == std::string::npos) {
                continue;
            }
            std::string user = line.substr(0, separator);
            uint64_t target = parse_hex40(line.substr(separator + 1));
            auto target_start = std::chrono::steady_clock::now();
            Password password = recover_one(target, table);
            double seconds = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - target_start
            ).count();
            std::cout << user << ':' << password_string(password)
                      << " (" << std::fixed << std::setprecision(2)
                      << seconds << "s)\n" << std::flush;
        }

        double total = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - started
        ).count();
        std::cout << "total " << std::fixed << std::setprecision(2)
                  << total << "s\n";
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
