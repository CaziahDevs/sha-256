#Overview
This project provides a custom implementation of the SHA-256 hashing algorithm in Python, demonstrating the complete algorithm without external dependencies, including:

1. Message preprocessing
2. Message padding
3. Compression function with bitwise operations
4. Hash computation


# Create an instance of the encryption class
enc = Encryption()

# Hash a message
hash_result = enc.sha256("Your message here")
print(hash_result)

#Testing
The implementation passes validation tests for standard test inputs, including:

Empty string
Simple messages
Long sequences
