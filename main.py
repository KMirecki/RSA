import sympy
from PIL import Image
import io
import matplotlib.pyplot as plt
import cv2
import numpy as np
import zlib

class Chunk:
    def __init__(self, length, name, length_translated, name_translated, data, checksum):
        self.length_translated = length_translated
        self.name_translated = name_translated
        self.length = length
        self.name = name
        self.data = data
        self.checksum = checksum
    
    def printInfo(self):
        return "\nDługość chunku:\t" + str(self.length_translated) + "\nNazwa chunku:\t" + str(self.name_translated)
    
    def printBytes(self):
        bytes_list = []
        bytes_list.extend(self.length)
        bytes_list.extend(self.name)
        bytes_list.extend(self.data)
        bytes_list.extend(self.checksum)
        return bytes_list

    def update_checksum(self):
        chunk_data = self.name + self.data
        self.checksum = zlib.crc32(bytes(chunk_data)).to_bytes(4, 'big')

    def encrypt_IDAT(self, public_key, product):
        encrypted_data = []
        for byte in self.data:
            encrypted_byte = encrypt(byte, public_key, product)
            encrypted_data.extend(encrypted_byte.to_bytes((product.bit_length() + 7) // 8, 'big'))
        self.data = encrypted_data
        self.length_translated = len(self.data)
        self.length = self.length_translated.to_bytes(4, 'big')
        self.update_checksum()
        self.length_translated+=12

    def decrypt_IDAT(self, private_key, product):
        decrypted_data = []
        key_size = (product.bit_length() + 7) // 8 
        for i in range(0, len(self.data), key_size):
            chunk = self.data[i:i + key_size]
            encrypted_byte = int.from_bytes(chunk, 'big')
            decrypted_byte = decrypt(encrypted_byte, private_key, product)
            decrypted_data.append(decrypted_byte)
        self.data = decrypted_data
        self.length_translated = len(self.data)
        self.length = self.length_translated.to_bytes(4, 'big')
        self.update_checksum()
        self.length_translated+=12
    
    def encrypt_decompressed_IDAT(self, public_key, product):
        decompressed_data = zlib.decompress(bytes(self.data))
        block_size = 4
        encrypted_data = []
        for i in range(0, len(decompressed_data), block_size):
            block = decompressed_data[i:i + block_size]
            block_int = int.from_bytes(block, 'big')
            encrypted_block = encrypt(block_int, public_key, product)
            encrypted_data.extend(encrypted_block.to_bytes((product.bit_length() + 7) // 8, 'big'))
        compressed_data = zlib.compress(bytes(encrypted_data))
        self.data = list(compressed_data)
        self.length_translated = len(self.data)
        self.length = self.length_translated.to_bytes(4, 'big')
        self.update_checksum()
        self.length_translated+=12
    
    def decrypt_decompressed_IDAT(self, private_key, product):
        decompressed_data = zlib.decompress(bytes(self.data))
        decrypted_data = []
        key_size = (product.bit_length() + 7) // 8
        block_size = 4
        for i in range(0, len(decompressed_data), key_size):
            chunk = decompressed_data[i:i + key_size]
            encrypted_block = int.from_bytes(chunk, 'big')
            decrypted_block = decrypt(encrypted_block, private_key, product)
            decrypted_data.extend(decrypted_block.to_bytes(block_size, 'big'))
        compressed_data = zlib.compress(bytes(decrypted_data))
        self.data = list(compressed_data)
        self.length_translated = len(self.data)
        self.length = self.length_translated.to_bytes(4, 'big')
        self.update_checksum()
        self.length_translated+=12

    def encrypt_with_lib():
        return 0
    
    def decrypt_with_lib():
        return 0

def save_decimal_data(png_file):
    decimal_data = []
    with open(png_file, 'rb') as f:
        binary_data = f.read()
        for byte in binary_data:
            decimal_data.append(byte)
    png_check = decimal_data[0:8]
    if png_check == [137, 80, 78, 71, 13, 10, 26, 10]:
        return decimal_data
    else:
        raise ValueError("File is not a PNG")

def chunk_name(chunk):
    chunk_name=''
    for byte in chunk:
        chunk_name += chr(byte)
    return chunk_name

def chunk_length(chunk):
    chunk_length = 12+int.from_bytes(chunk)
    return chunk_length

def chunk_decoder(chunk, chunks_list):
    if len(chunk) >= 12:
        length = chunk[0:4]
        length_translated = chunk_length(chunk[0:4])
        name = chunk[4:8]
        name_translated = chunk_name(chunk[4:8])
        data = chunk[8:length_translated-4]
        checksum = chunk[length_translated-4:length_translated]
        new_chunk = Chunk(length, name, length_translated, name_translated, data, checksum)
        chunks_list.append(new_chunk)
        remaining_chunk = chunk[length_translated:]
        chunk_decoder(remaining_chunk, chunks_list)
    return chunks_list

def generate_public_key(totient):
    while True:
        public_key = sympy.randprime(2, totient)
        if sympy.gcd(public_key, totient) == 1:
            return public_key

def generate_private_key(public_key, totient):
    return pow(public_key, -1, totient)

def generate_keys(bits=2048):
    p = sympy.randprime(pow(2, (bits // 2 - 1)), pow(2, (bits // 2)))
    q = sympy.randprime(pow(2, (bits // 2 - 1)), pow(2, (bits // 2)))
    while p == q:
        q = sympy.randprime(pow(2, (bits // 2 - 1)), pow(2, (bits // 2)))    
    product = p * q
    totient = (p - 1) * (q - 1)
    public_key = generate_public_key(totient)
    private_key = generate_private_key(public_key, totient)
    return product, public_key, private_key

def encrypt(message, public_key, product):
    return pow(message, public_key, product)

def decrypt(encrypted_message, private_key, product):
    return pow(encrypted_message, private_key, product)

if __name__ == "__main__":
    product, public_key, private_key = generate_keys(bits=2048)
    print(public_key, " ", private_key)
    png_file = 'pp0n6a08.png'
    dec_data = save_decimal_data(png_file)
    png_file_signature = [137, 80, 78, 71, 13, 10, 26, 10]
    chunks_list = []
    encrypted_data = []
    encrypted_decompressed = []
    encrypted_data.extend(png_file_signature)
    encrypted_decompressed.extend(png_file_signature)
    if dec_data[0:8] == png_file_signature:
        print("Pierwsze 8 bajtow pliku - sygnatura PNG:\n", dec_data[0:8])  
        chunks_list = chunk_decoder(dec_data[8:], chunks_list)
        chunks_list2 = chunks_list

        #skompresowane
        for chunk in chunks_list:
            if chunk.name_translated == "IDAT":
                if chunk.length_translated == 0:
                    break
                else:
                    print("oryginalny")
                    print(chunk.printInfo())
                    chunk.encrypt_IDAT(public_key, product)
                    encrypted_data.extend(chunk.printBytes())
                    print("po szyfrowaniu")
                    print(chunk.printInfo())
                    chunk.decrypt_IDAT(private_key, product)
                    #print(chunk.printBytes())
                    print("po deszyfrowaniu")
                    print(chunk.printInfo())
            else:
                encrypted_data.extend(chunk.printBytes())
          
        decrypted_data = []
        decrypted_data.extend(png_file_signature)
        for chunk in chunks_list:
            decrypted_data.extend(chunk.printBytes())

        with open("decrypted.png","wb") as f:
            f.write(bytes(decrypted_data))
        
        with open("encrypted.png","wb") as f:
            f.write(bytes(encrypted_data))
        
        image = Image.open(io.BytesIO(bytes(decrypted_data)))
        image1 = Image.open("decrypted.png")

        #zdekompresowane
        for chunk in chunks_list2:
            if chunk.name_translated == "IDAT":
                if chunk.length_translated == 0:
                    break
                else:
                    print("oryginalny")
                    print(chunk.printInfo())
                    chunk.encrypt_decompressed_IDAT(public_key, product)
                    encrypted_decompressed.extend(chunk.printBytes())
                    print("po szyfrowaniu po dekompresji")
                    print(chunk.printInfo())
                    chunk.decrypt_decompressed_IDAT(private_key, product)
                    #print(chunk.printBytes())
                    print("po deszyfrowaniu po kompresji")
                    print(chunk.printInfo())
            else:
                encrypted_decompressed.extend(chunk.printBytes())

        decrypted_data2 = []
        decrypted_data2.extend(png_file_signature)
        for chunk in chunks_list2:
            decrypted_data2.extend(chunk.printBytes())

        with open("encrypted_decompressed.png","wb") as f:
            f.write(bytes(encrypted_decompressed))

        with open("decrypted_decompressed.png","wb") as f:
            f.write(bytes(decrypted_data2))

        image2 = Image.open("decrypted_decompressed.png")

        plt.figure()
        plt.subplot(1, 3, 1)
        plt.imshow(image)
        plt.title('original image')
        plt.axis('off')
        plt.subplot(1, 3, 2)
        plt.imshow(image1)
        plt.title('decrypted image')
        plt.axis('off')
        plt.subplot(1, 3, 3)
        plt.imshow(image2)
        plt.title('decompressed decrypted image')
        plt.axis('off')
        plt.show()

    else:
        raise TypeError("File is not a PNG")