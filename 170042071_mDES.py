#Language: python 3
#Author: Razia Zaman Ela
#id: 170042071
#email:razela99@gmail.com






class MiniDES:

    def __init__(self):
        self.pc_1 = [17, 9, 1, 18, 10, 2, 19, 11, 3, 23, 15, 7, 22, 14, 6, 21, 13, 5, 20, 12, 4]
        self.pc_2 = [17, 11, 1, 5, 3, 15, 6, 18, 10, 19, 12, 4, 8, 16, 9, 20, 13, 2]
        self.ls_list = [1, 1, 2, 2, 2, 2]

        self.ip = [18, 10, 2, 20, 12, 4, 22, 14, 6, 24, 16, 8, 17, 9, 1, 19, 11, 3, 21, 13, 5, 23, 15, 7]
        self.ip_1 = [15, 3, 18, 6, 21, 9, 24, 12, 14, 2, 17, 5, 20, 8, 23, 11, 13, 1, 16, 4, 19, 7, 22, 10]

        self.e_table = [12, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 1]
        self.p_table = [7, 12, 1, 5, 10, 2, 8, 3, 9, 6, 11, 4]

        self.s0 = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                   [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                   [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                   [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]

        self.s1 = [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                   [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                   [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                   [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]

        self.s2 = [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                   [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                   [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                   [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]]

    def XOR(self, n1, n2, d):
        return bin(int(n1, 2) ^ int(n2, 2))[2:].zfill(d)

    def encryption(self, plaintext, key):
        # convert hex digits to binary
        self.plaintext = bin(int(plaintext, 16))[2:].zfill(24)

        self.key = bin(int(key, 16))[2:].zfill(24)
        # generate 6 subkey
        self.sub_key = self.sub_key_generation()
        #print('Sub Key', self.sub_key)
        # intial permutation using ip table
        IP = self.permute(self.plaintext, self.ip)
        output = IP

        for i in range(0, 6):
            # split into two slice Left and right
            L, R = output[0:12], output[12:24]

            # permutate using E_Table
            E_Table = self.permute(R, self.e_table)

            # XOR with key in each iterataion
            XOR_with_key = self.XOR(E_Table, self.sub_key[i], 18)
            # generate s_box output
            s_box = self.s_box(XOR_with_key)
            # permutate using p_box
            p_box = self.permute(s_box, self.p_table)
            # XOR with left slice
            XOR_with_L = self.XOR(p_box, L, 12)
            # combined output
            output = R + XOR_with_L

        FinalSwap = output[12:24] + output[0:12]
        # permutate finalswap using ip_1
        IP_1 = self.permute(FinalSwap, self.ip_1)
        # convert IP_1 output into hex
        cipherText = hex(int(IP_1, 2))[2:].zfill(6)
        return cipherText

    def decryption(self, ciphertext, key):
        self.ciphertext = bin(int(ciphertext, 16))[2:].zfill(24)
        self.key = bin(int(key, 16))[2:].zfill(24)
        self.sub_key = self.sub_key_generation()
        IP = self.permute(self.ciphertext, self.ip)

        output = IP
        # using subkey in reversed order
        for i in reversed(range(0, 6)):
            # split into two slice Left and right
            L, R = output[0:12], output[12:24]

            # permutate using E_Table
            E_Table = self.permute(R, self.e_table)

            # XOR with key in each iterataion
            XOR_with_key = self.XOR(E_Table, self.sub_key[i], 18)
            # generate s_box output
            s_box = self.s_box(XOR_with_key)
            # permutate using p_box
            p_box = self.permute(s_box, self.p_table)
            # XOR with left slice
            XOR_with_L = self.XOR(p_box, L, 12)
            # combined output
            output = R + XOR_with_L

        FinalSwap = output[12:24] + output[0:12]
        # permutate finalswap using ip_1
        IP_1 = self.permute(FinalSwap, self.ip_1)
        # convert IP_1 output into hex
        plaintext = hex(int(IP_1, 2))[2:].zfill(6)
        return plaintext

    def left_shift(self, num, n):
        s = ""
        for i in range(n):
            for j in range(1, len(num)):
                s = s + num[j]
            s = s + num[0]
            num = s
            s = ""
        return num

    def sub_key_generation(self):
        pc_1 = self.permute(self.key, self.pc_1)
        c, d = pc_1[0:10], pc_1[10:21]
        s_key = []
        for s in self.ls_list:
            c = self.left_shift(c, s)
            d = self.left_shift(d, s)
            pc_2 = self.permute(c + d, self.pc_2)
            s_key.append(pc_2)

        return s_key

    def s_box(self, num):
        a, b, c = num[0:6], num[6:12], num[12:18]

        s0 = bin(self.s0[int(a[0] + a[5], 2)][int(a[1:5], 2)])[2:].zfill(4)
        s1 = bin(self.s1[int(b[0] + b[5], 2)][int(b[1:5], 2)])[2:].zfill(4)
        s2 = bin(self.s2[int(c[0] + c[5], 2)][int(c[1:5], 2)])[2:].zfill(4)
        s_box = s0 + s1 + s2
        return s_box

    def permute(self, num, arr):
        permutation = ""
        for i in range(0, len(arr)):
            permutation = permutation + num[arr[i] - 1]
        return permutation



m = MiniDES()
#print('Plaintext: ', 'E1A000', 'Key: ', 'ABCFEF', '\n', 'Encrypted : ', m.encryption('E1A000', 'ABCFEF'))
#print('Ciphertext: ', '6D81AE', 'Key: ', 'ABCFEF', '\n', 'Decrypted : ', m.decryption('6D81AE', 'ABCFEF'))

option=input("Enter 'E' for Encryption, 'D' for Decryption: ")
key=input("Enter Key: ")

if option =='E':
    plaintext = input("Enter Plaintext: ")
    print('Ciphertext: ',m.encryption(plaintext, key))
elif option== 'D':
    ciphertext=input("Enter Ciphertext: ")
    print('Decrypted Plaintext: ', m.decryption(ciphertext, key))


