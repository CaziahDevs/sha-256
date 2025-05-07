class Encryption():
    def __init__(self):
        # initial hash values
        self.hash = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ] 
        
        # constants for compression function
        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

    
    def preprocessing(self, message):
        original = message.encode('utf-8') # utf-8 encoding
        encoded = bytearray(original)

        encoded += b'\x80' # append 1 bit
        
        while len(encoded) % 64 != 56:
            encoded += b'\x00' # append 0 bits

        # append length of message
        bitlength = len(original) * 8
        # Convert to 8 bytes (64 bits) in big-endian order
        encoded += bitlength.to_bytes(8, byteorder='big') 

        return encoded
    
    def right_rotate(self, x, n):
        return ((x >> n) | (x << (32-n))) & 0xFFFFFFFF

    def right_shift(self, x, n):
        return (x >> n) & 0xFFFFFFFF
    
    def process_chunk(self, chunk):
        # Initialize the 64 working variables, 1 byte for 8 bits of the 512 bit chunk
        W = [0]*64
        #Extract the first 16 words from the chunk
        for i in range(16):
            W[i] = int.from_bytes(chunk[i*4:i*4+4], byteorder='big')
        
        # Extend the first 16 words into the remaining 48 words
        for i in range(16, 64):
            s0 = self.right_rotate(W[i-15], 7) ^ self.right_rotate(W[i-15], 18) ^ self.right_shift(W[i-15], 3)
            s1 = self.right_rotate(W[i-2], 17) ^ self.right_rotate(W[i-2], 19) ^ self.right_shift(W[i-2], 10)
            W[i] = (W[i - 16] + s0 + W[i-7] + s1) & 0xFFFFFFFF

        # Initialize hash values for this chunk
        a, b, c, d, e, f, g, h = self.hash

        for i in range(0,64):
            s1 = self.right_rotate(e, 6) ^ self.right_rotate(e, 11) ^ self.right_rotate(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + s1 + ch + self.k[i] + W[i]) & 0xFFFFFFFF
            s0 = self.right_rotate(a, 2) ^ self.right_rotate(a, 13) ^ self.right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c) 
            temp2 = (s0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Add this chunk's hash to result so far
        for i in range(8):
            self.hash[i] = (self.hash[i] + [a, b, c, d, e, f, g, h][i]) & 0xFFFFFFFF


    def sha256(self, message):

        #reset for new message
        self.hash = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        
        message_byte_array = self.preprocessing(message)

        # process message in 512-bit chunks
        for i in range(0, len(message_byte_array), 64):
            chunk = message_byte_array[i:i+64]
            self.process_chunk(chunk)

        # Convert hash values to hexadecimal string
        return ''.join(f'{h:08x}' for h in self.hash)

def test_sha256():
    enc = Encryption()
    
    # Test case 1: Empty string
    result = enc.sha256("")
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    print(f"Test 1 {'PASSED' if result == expected else 'FAILED'}")
    print(f"  Got:      {result}")
    print(f"  Expected: {expected}")
    
    # Test case 2: Simple message
    result = enc.sha256("abc")
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    print(f"Test 2 {'PASSED' if result == expected else 'FAILED'}")
    print(f"  Got:      {result}")
    print(f"  Expected: {expected}")
    
    # Test case 3: Longer message
    result = enc.sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    print(f"Test 3 {'PASSED' if result == expected else 'FAILED'}")
    print(f"  Got:      {result}")
    print(f"  Expected: {expected}")
    
    # Test case 4: Million 'a's (this will take a bit longer)
    # Uncomment if you want to run it
    result = enc.sha256("a" * 1000000)
    expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    print(f"Test 4 {'PASSED' if result == expected else 'FAILED'}")
    print(f"  Got:      {result}")
    print(f"  Expected: {expected}")

test_sha256()       