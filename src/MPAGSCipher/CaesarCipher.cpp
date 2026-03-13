#include "CaesarCipher.hpp"
#include "Alphabet.hpp"

#include <chrono>
#include <future>
#include <iostream>
#include <string>
/**
 * \file CaesarCipher.cpp
 * \brief Contains the implementation of the CaesarCipher class
 */

CaesarCipher::CaesarCipher(const std::size_t key) : key_{key % Alphabet::size}
{
}

CaesarCipher::CaesarCipher(const std::string& key) : key_{0}
{
    // We have the key as a string, but the Caesar cipher needs an unsigned long, so we first need to convert it
    // We default to having a key of 0, i.e. no encryption, if no (valid) key was provided on the command line
    if (!key.empty()) {
        // First, explicitly check for negative numbers - these will convert successfully but will not lead to expected results
        if (key.front() == '-') {
            throw InvalidKey(
                "Caesar cipher requires a positive long integer key, the supplied key (" +
                key + ") could not be successfully converted");
        }
        // The conversion function will throw one of two possible exceptions
        // if the string does not represent a valid unsigned long integer
        try {
            key_ = std::stoul(key) % Alphabet::size;
        } catch (const std::invalid_argument&) {
            throw InvalidKey(
                "Caesar cipher requires a positive long integer key, the supplied key (" +
                key + ") could not be successfully converted");
        } catch (const std::out_of_range&) {
            throw InvalidKey(
                "Caesar cipher requires a positive long integer key, the supplied key (" +
                key + ") could not be successfully converted");
        }
    }
}

std::string CaesarCipher::applyCipher(const std::string& inputText,
                                      const CipherMode cipherMode) const
{
    // Create the output string
    std::string outputText;
    outputText.reserve(inputText.size());

    constexpr int NTHREADS{8};
    std::vector<std::future<std::string>> futures;
    auto processChunk = [this, cipherMode](const std::string& chunk) {
        std::string outputChunk;
        outputChunk.reserve(chunk.size());

        // Loop over the input text
        char processedChar{'x'};
        for (const auto& origChar : chunk) {
            // For each character in the input text, find the corresponding position in
            // the alphabet by using an indexed loop over the alphabet container
            for (std::size_t i{0}; i < Alphabet::size; ++i) {
                if (origChar == Alphabet::alphabet[i]) {
                    // Apply the appropriate shift (depending on whether we're encrypting
                    // or decrypting) and determine the new character
                    // Can then break out of the loop over the alphabet
                    switch (cipherMode) {
                        case CipherMode::Encrypt:
                            processedChar =
                                Alphabet::alphabet[(i + key_) % Alphabet::size];
                            break;
                        case CipherMode::Decrypt:
                            processedChar =
                                Alphabet::alphabet[(i + Alphabet::size - key_) %
                                                   Alphabet::size];
                            break;
                    }
                    break;
                }
            }

            // Add the new character to the output text
            outputChunk += processedChar;
        }

        return outputChunk;
    };

    std::size_t chunkSize = inputText.size() / NTHREADS;
    for (std::size_t i{0}; i < NTHREADS; ++i) {
        std::size_t start = i * chunkSize;
        std::size_t end =
            (i == NTHREADS - 1) ? inputText.size() : (i + 1) * chunkSize;
        futures.push_back(std::async(std::launch::async, processChunk,
                                     inputText.substr(start, end - start)));
    }

    for (auto& future : futures) {
        std::future_status status{std::future_status::ready};
        do {
            constexpr int WAIT_MILISECONDS{100};
            status =
                future.wait_for(std::chrono::milliseconds(WAIT_MILISECONDS));
        } while (status != std::future_status::ready);

        outputText += future.get();
    }

    return outputText;
}
