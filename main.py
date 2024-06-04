import sympy
from PIL import Image
import io
import matplotlib.pyplot as plt
import cv2
import numpy as np
import zlib

class Chunk:
    def __init__(self, length, name, length_translated, name_translated, data, checksum):
        #wartości liczbowe/tekstowe zamiast listy bajtów
        self.length_translated = length_translated
        self.name_translated = name_translated
        self.length = length
        self.name = name
        self.data = data
        self.checksum = checksum
    
    def printInfo(self):
        return "\nDługość chunku:\t" + str(self.length_translated) + "\nNazwa chunku:\t" + str(self.name_translated)
    
    #wypisanie wszystkich bajtów chunka
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
            encrypted_byte = encrypt(byte,public_key,product)
            encrypted_data.append(encrypted_byte)
        self.data = encrypted_data

    def decrypt_IDAT(self, private_key, product):
        decrypted_data = []
        for byte in self.data:
            decrypted_byte = decrypt(byte,private_key,product)
            decrypted_data.append(decrypted_byte)
        self.data = decrypted_data

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
    if(len(chunk)>=12):
        length = chunk[0:4]
        length_translated = chunk_length(chunk[0:4])
        name = chunk[4:8]
        name_translated = chunk_name(chunk[4:8])
        data = chunk[8:length_translated-4]
        checksum = chunk[length_translated-4:length_translated]
        new_chunk = Chunk(length,name,length_translated,name_translated,data,checksum)
        chunks_list.append(new_chunk)
        remaining_chunk=chunk[length_translated:]
        chunk_decoder(remaining_chunk, chunks_list)
    return chunks_list

def generate_public_key(totient):
    while True:
        public_key = sympy.randprime(2, totient)
        if sympy.gcd(public_key, totient) == 1:
            return public_key

def generate_private_key(public_key, totient):
    return pow(public_key,-1,totient)

def generate_keys():
    p = sympy.randprime(2, 15)
    q = sympy.randprime(2, 15)
    while p == q:
        q = sympy.randprime(2, 15)
    product = p * q
    totient = (p - 1) * (q - 1)
    public_key = generate_public_key(totient)
    private_key = generate_private_key(public_key, totient)
    #print(f"p = {p}, q = {q}, product = {product}, totient = {totient}, public key = {public_key}, private key = {private_key}")
    return product, public_key, private_key

def encrypt(message, public_key, product):
    return pow(message, public_key, product)

def decrypt(encrypted_message, private_key, product):
    return pow(encrypted_message, private_key, product)

if __name__ == "__main__":
    #message = 60
    product, public_key, private_key = generate_keys()
    #encrypted_message = encrypt(message, public_key, product)
    #print(f"Encrypted message: {encrypted_message}")
    #decrypted_message = decrypt(encrypted_message, private_key, product)
    #print(f"Decrypted message: {decrypted_message}")
    #png_file = 'Lenna_(test_image).png'
    #png_file = 'PNG_transparency_demonstration_1.png'
    #png_file = 'pnglogo--povray-3.7--black826--800x600.png'
    png_file = 'pp0n6a08.png'
    dec_data = save_decimal_data(png_file)
    png_file_signature = [137, 80, 78, 71, 13, 10, 26, 10]
    chunks_list=[]
    if(dec_data[0:8]==png_file_signature):
        print("Pierwsze 8 bajtow pliku - sygnatura PNG:\n", dec_data[0:8])  
        chunks_list = chunk_decoder(dec_data[8:],chunks_list)
        for chunk in chunks_list:
            print(chunk.printInfo())
            match chunk.name_translated:
                case "IDAT":
                    if(chunk.length_translated==0):
                        break
                    else:
                        chunk.encrypt_IDAT(public_key, product)
                        chunk.update_checksum()
                        chunk.decrypt_IDAT(private_key,product)
                        chunk.update_checksum()
                
        data_bytes = bytes(dec_data)
        image = Image.open(io.BytesIO(data_bytes))

        #print(newer_chunks_list)
        #with open("plik.png","wb") as f:
        #    f.write(bytes(newer_chunks_list))
        
        #print(new_chunks_list)
        #with open("plik1.png","wb") as f:
        #    f.write(bytes(new_chunks_list))

        #new_data_bytes = bytes(new_chunks_list)
        #image1 = Image.open(io.BytesIO(new_data_bytes))

        #newer_data_bytes = bytes(newer_chunks_list)
        #image1 = Image.open(io.BytesIO(newer_data_bytes))

        #with open("lena.png", "wb") as f:
        #    f.write(bytes(newer_chunks_list))
        
        #with open("lena1.png", "wb") as f:
        #    f.write(bytes(newer_chunks_list))

        plt.figure()
        plt.subplot(1, 2, 1)
        plt.imshow(image)
        plt.title('Image')
        plt.axis('off')
        plt.subplot(1, 2, 2)
        plt.imshow(image1)
        plt.title('Image')
        plt.axis('off')
        plt.show()

    else:
        raise TypeError("File is not a png")