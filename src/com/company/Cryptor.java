package com.company;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

public class Cryptor {

    private static final int Nb = 4; // число столбцов (32-битных слов) в state (для AES-128 это значение равно 4)
    private static final int Nk = 4; // размер ключа в 32-битных словах (для AES-128 это значение равно 4)
    private static final int Nr = 10; // количество раундов (для AES-128 это значение равно 10)
    private static final int blockSize = 16; //размер блока. в данном случае 16 байт
    private static final byte[][] Sbox = {                //S-box
            {(byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5,
                    (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76},
            {(byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47, (byte) 0xf0,
                    (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0},
            {(byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f, (byte) 0xf7, (byte) 0xcc,
                    (byte) 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31, (byte) 0x15},
            {(byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a,
                    (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2, (byte) 0x75},
            {(byte) 0x09, (byte) 0x83, (byte) 0x2c, (byte) 0x1a, (byte) 0x1b, (byte) 0x6e, (byte) 0x5a, (byte) 0xa0,
                    (byte) 0x52, (byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29, (byte) 0xe3, (byte) 0x2f, (byte) 0x84},
            {(byte) 0x53, (byte) 0xd1, (byte) 0x00, (byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1, (byte) 0x5b,
                    (byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39, (byte) 0x4a, (byte) 0x4c, (byte) 0x58, (byte) 0xcf},
            {(byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d, (byte) 0x33, (byte) 0x85,
                    (byte) 0x45, (byte) 0xf9, (byte) 0x02, (byte) 0x7f, (byte) 0x50, (byte) 0x3c, (byte) 0x9f, (byte) 0xa8},
            {(byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, (byte) 0x38, (byte) 0xf5,
                    (byte) 0xbc, (byte) 0xb6, (byte) 0xda, (byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2},
            {(byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec, (byte) 0x5f, (byte) 0x97, (byte) 0x44, (byte) 0x17,
                    (byte) 0xc4, (byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d, (byte) 0x19, (byte) 0x73},
            {(byte) 0x60, (byte) 0x81, (byte) 0x4f, (byte) 0xdc, (byte) 0x22, (byte) 0x2a, (byte) 0x90, (byte) 0x88,
                    (byte) 0x46, (byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde, (byte) 0x5e, (byte) 0x0b, (byte) 0xdb},
            {(byte) 0xe0, (byte) 0x32, (byte) 0x3a, (byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5c,
                    (byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, (byte) 0x79},
            {(byte) 0xe7, (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5, (byte) 0x4e, (byte) 0xa9,
                    (byte) 0x6c, (byte) 0x56, (byte) 0xf4, (byte) 0xea, (byte) 0x65, (byte) 0x7a, (byte) 0xae, (byte) 0x08},
            {(byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6,
                    (byte) 0xe8, (byte) 0xdd, (byte) 0x74, (byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a},
            {(byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xf6, (byte) 0x0e,
                    (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, (byte) 0x1d, (byte) 0x9e},
            {(byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94,
                    (byte) 0x9b, (byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, (byte) 0x55, (byte) 0x28, (byte) 0xdf},
            {(byte) 0x8c, (byte) 0xa1, (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42, (byte) 0x68,
                    (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0, (byte) 0x54, (byte) 0xbb, (byte) 0x16}
    };
    private static final byte[][] InvSbox = {
            {(byte) 0x52, (byte) 0x09, (byte) 0x6a, (byte) 0xd5, (byte) 0x30, (byte) 0x36, (byte) 0xa5, (byte) 0x38,
                    (byte) 0xbf, (byte) 0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb},
            {(byte) 0x7c, (byte) 0xe3, (byte) 0x39, (byte) 0x82, (byte) 0x9b, (byte) 0x2f, (byte) 0xff, (byte) 0x87,
                    (byte) 0x34, (byte) 0x8e, (byte) 0x43, (byte) 0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9, (byte) 0xcb},
            {(byte) 0x54, (byte) 0x7b, (byte) 0x94, (byte) 0x32, (byte) 0xa6, (byte) 0xc2, (byte) 0x23, (byte) 0x3d,
                    (byte) 0xee, (byte) 0x4c, (byte) 0x95, (byte) 0x0b, (byte) 0x42, (byte) 0xfa, (byte) 0xc3, (byte) 0x4e},
            {(byte) 0x08, (byte) 0x2e, (byte) 0xa1, (byte) 0x66, (byte) 0x28, (byte) 0xd9, (byte) 0x24, (byte) 0xb2,
                    (byte) 0x76, (byte) 0x5b, (byte) 0xa2, (byte) 0x49, (byte) 0x6d, (byte) 0x8b, (byte) 0xd1, (byte) 0x25},
            {(byte) 0x72, (byte) 0xf8, (byte) 0xf6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16,
                    (byte) 0xd4, (byte) 0xa4, (byte) 0x5c, (byte) 0xcc, (byte) 0x5d, (byte) 0x65, (byte) 0xb6, (byte) 0x92},
            {(byte) 0x6c, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9, (byte) 0xda,
                    (byte) 0x5e, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84},
            {(byte) 0x90, (byte) 0xd8, (byte) 0xab, (byte) 0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3, (byte) 0x0a,
                    (byte) 0xf7, (byte) 0xe4, (byte) 0x58, (byte) 0x05, (byte) 0xb8, (byte) 0xb3, (byte) 0x45, (byte) 0x06},
            {(byte) 0xd0, (byte) 0x2c, (byte) 0x1e, (byte) 0x8f, (byte) 0xca, (byte) 0x3f, (byte) 0x0f, (byte) 0x02,
                    (byte) 0xc1, (byte) 0xaf, (byte) 0xbd, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8a, (byte) 0x6b},
            {(byte) 0x3a, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4f, (byte) 0x67, (byte) 0xdc, (byte) 0xea,
                    (byte) 0x97, (byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6, (byte) 0x73},
            {(byte) 0x96, (byte) 0xac, (byte) 0x74, (byte) 0x22, (byte) 0xe7, (byte) 0xad, (byte) 0x35, (byte) 0x85,
                    (byte) 0xe2, (byte) 0xf9, (byte) 0x37, (byte) 0xe8, (byte) 0x1c, (byte) 0x75, (byte) 0xdf, (byte) 0x6e},
            {(byte) 0x47, (byte) 0xf1, (byte) 0x1a, (byte) 0x71, (byte) 0x1d, (byte) 0x29, (byte) 0xc5, (byte) 0x89,
                    (byte) 0x6f, (byte) 0xb7, (byte) 0x62, (byte) 0x0e, (byte) 0xaa, (byte) 0x18, (byte) 0xbe, (byte) 0x1b},
            {(byte) 0xfc, (byte) 0x56, (byte) 0x3e, (byte) 0x4b, (byte) 0xc6, (byte) 0xd2, (byte) 0x79, (byte) 0x20,
                    (byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe, (byte) 0x78, (byte) 0xcd, (byte) 0x5a, (byte) 0xf4},
            {(byte) 0x1f, (byte) 0xdd, (byte) 0xa8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xc7, (byte) 0x31,
                    (byte) 0xb1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xec, (byte) 0x5f},
            {(byte) 0x60, (byte) 0x51, (byte) 0x7f, (byte) 0xa9, (byte) 0x19, (byte) 0xb5, (byte) 0x4a, (byte) 0x0d,
                    (byte) 0x2d, (byte) 0xe5, (byte) 0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c, (byte) 0xef},
            {(byte) 0xa0, (byte) 0xe0, (byte) 0x3b, (byte) 0x4d, (byte) 0xae, (byte) 0x2a, (byte) 0xf5, (byte) 0xb0,
                    (byte) 0xc8, (byte) 0xeb, (byte) 0xbb, (byte) 0x3c, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61},
            {(byte) 0x17, (byte) 0x2b, (byte) 0x04, (byte) 0x7e, (byte) 0xba, (byte) 0x77, (byte) 0xd6, (byte) 0x26,
                    (byte) 0xe1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0c, (byte) 0x7d}
    };


    private static final byte[] Rcon = {        //Rcon — постоянный массив для генерации ключей
            (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x08, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x20, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x40, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x1B, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x36, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };


    //ОСНОВНОЙ МЕТОД ENCRYPTO
    public static void encrypto(String stringPathInputFile, String stringPathOutputFile, String stringKey) throws IOException {      //еще он возвращает путь к аутпуту
            byte[] key = hexStringToByteArray(stringKey);
            byte[][][] roundKeys = getRoundKeys(key);

            FileInputStream inputStream = new FileInputStream(stringPathInputFile);
            byte[] inputBytes = inputStream.readAllBytes();

            byte[] paddedInputBytes = addPadding(inputBytes);

            int numBlocks = paddedInputBytes.length / blockSize;
            byte[] outputBytes = new byte[numBlocks * blockSize];

            for (int i = 0; i < numBlocks; i++) {
                byte[][] state = new byte[4][Nb];
                for (int j = 0; j < blockSize; j++) {
                    state[j % 4][j / 4] = paddedInputBytes[i * blockSize + j];
                }

                addRoundKey(state, roundKeys[0]);

                for (int r = 1; r < Nr; r++) {
                    subBytes(state);
                    shiftRows(state);
                    mixColumns(state);
                    addRoundKey(state, roundKeys[r]);
                }

                subBytes(state);
                shiftRows(state);
                addRoundKey(state, roundKeys[Nr]);

                for (int j = 0; j < blockSize; j++) {
                    outputBytes[i * blockSize + j] = state[j % 4][j / 4];
                }
            }

            String outputFileName = new File(stringPathInputFile).getName() + ".jabaes";
            FileOutputStream outputStream = new FileOutputStream(stringPathOutputFile + "/" + outputFileName);
            outputStream.write(outputBytes);
            outputStream.close();
            new First64Bytes(stringPathInputFile, stringPathOutputFile + "/" + outputFileName);
    }


    //ГЕНЕРАЦИЯ КЛЮЧЕЙ
    //преобразование строки ключа в вид байтовой матрицы
    public static byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] byteArray = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            byteArray[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }

        return byteArray;
    }

    //ключи для раундов
    private static byte[][][] getRoundKeys(byte[] key) {
        byte[][][] roundKeys = new byte[Nr + 1][4][Nb];

        byte[][] w = getKeySchedule(key);

        for (int i = 0; i < roundKeys.length; i++) {
            for (int j = 0; j < Nb; j++) {
                for (int k = 0; k < 4; k++) {
                    roundKeys[i][j][k] = w[i * Nb + j][k];
                }
            }
        }
        return roundKeys;
    }

    //расписание ключей
    private static byte[][] getKeySchedule(byte[] key) {
        byte[][] w = new byte[Nb * (Nr + 1)][4];
        byte[] temp = new byte[4];

        for (int i = 0; i < Nk; i++) {
            w[i] = new byte[]{key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]};
        }

        for (int i = Nk; i < w.length; i++) {
            for (int t = 0; t < 4; t++) {
                temp[t] = w[i - 1][t];
            }
            if (i % Nk == 0) {
                temp = subWord(rotateWord(temp));
                temp[0] ^= Rcon[i / Nk];
            } else if (Nk > 6 && i % Nk == 4) {
                temp = subWord(temp);
            }
            w[i] = xorWords(w[i - Nk], temp);
        }

        return w;
    }


    //сопоставление слов с S_box
    private static byte[] subWord(byte[] word) {
        byte[] result = new byte[4];
        for (int i = 0; i < 4; i++) {
            int row = (word[i] >> 4) & 0x0f;
            int col = word[i] & 0x0f;
            result[i] = Sbox[row][col];
        }
        return result;
    }

    //сдвиг элементов в слове
    private static byte[] rotateWord(byte[] word) {
        byte[] result = new byte[4];
        System.arraycopy(word, 1, result, 0, 3);
        result[3] = word[0];
        return result;
    }

    //xor слов
    private static byte[] xorWords(byte[] word1, byte[] word2) {
        byte[] result = new byte[word1.length];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (word1[i] ^ word2[i]);
        }
        return result;
    }

    //ОПЕРАЦИИ с STATE

    //прибавить раундовый ключ
    private static void addRoundKey(byte[][] state, byte[][] roundKey) {
        for (int c = 0; c < Nb; c++) {
            for (int r = 0; r < 4; r++) {
                state[r][c] ^= roundKey[r][c];
            }
        }
    }

    //сопоставление блока с S-box
    private static void subBytes(byte[][] state) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < Nb; c++) {
                state[r][c] = Sbox[(state[r][c] & 0xf0) >> 4][state[r][c] & 0x0f];
            }
        }
    }

    //смещение строк
    private static void shiftRows(byte[][] state) {
        byte[] t = new byte[4];
        for (int r = 1; r < 4; r++) {
            for (int c = 0; c < Nb; c++) {
                t[c] = state[r][(c + r) % Nb];
            }
            for (int c = 0; c < Nb; c++) {
                state[r][c] = t[c];
            }
        }
    }

    //умножение каждого столбца на особую матрицу
    private static void mixColumns(byte[][] state) {
        for (int c = 0; c < Nb; c++) {
            byte[] column = new byte[4];
            for (int r = 0; r < 4; r++) {
                column[r] = state[r][c];
            }
            state[0][c] = (byte) (mulBy2(column[0]) ^ mulBy3(column[1]) ^ column[2] ^ column[3]);
            state[1][c] = (byte) (column[0] ^ mulBy2(column[1]) ^ mulBy3(column[2]) ^ column[3]);
            state[2][c] = (byte) (column[0] ^ column[1] ^ mulBy2(column[2]) ^ mulBy3(column[3]));
            state[3][c] = (byte) (mulBy3(column[0]) ^ column[1] ^ column[2] ^ mulBy2(column[3]));
        }
    }

    private static byte mulBy2(byte b) {

        if ((b & 0x80) == 0) {
            return (byte) (b << 1);
        } else {
            return (byte) ((b << 1) ^ 0x1b);
        }
    }

    private static byte mulBy3(byte b) {
        return (byte) (mulBy2(b) ^ b);
    }

    //DECRYPTO

    public static void decrypto(String stringPathInputFile, String stringPathOutputFile, String stringKey) throws IOException {
            byte[] inputBytes = Files.readAllBytes(Paths.get(stringPathInputFile));

            byte[] key = hexStringToByteArray(stringKey);
            byte[][][] roundKeys = getRoundKeys(key);
            int numBlocks = inputBytes.length / blockSize;

            byte[] outputBytes = new byte[numBlocks * blockSize];

            for (int block = 0; block < numBlocks; block++) {
                byte[] blockBytes = Arrays.copyOfRange(inputBytes, block * blockSize, (block + 1) * blockSize);

                byte[][] state = new byte[4][Nb];
                for (int i = 0; i < 4; i++) {
                    for (int j = 0; j < Nb; j++) {
                        state[i][j] = blockBytes[i + 4 * j];
                    }
                }

                addRoundKey(state, roundKeys[Nr]);

                for (int round = Nr - 1; round >= 1; round--) {
                    invShiftRows(state);
                    invSubBytes(state);
                    addRoundKey(state, roundKeys[round]);
                    invMixColumns(state);
                }
                invShiftRows(state);
                invSubBytes(state);
                addRoundKey(state, roundKeys[0]);

                for (int i = 0; i < 4; i++) {
                    for (int j = 0; j < Nb; j++) {
                        outputBytes[i + 4 * j + block * blockSize] = state[i][j];
                    }
                }

                for (int j = 0; j < blockSize; j++) {
                    outputBytes[block * blockSize + j] = state[j % 4][j / 4];
                }

                outputBytes = removePadding(outputBytes);
            }

            String outputFileName = new File(stringPathInputFile).getName();
            outputFileName = "dec_" + outputFileName.substring(0, outputFileName.length() - 6);
            FileOutputStream outputStream = new FileOutputStream(stringPathOutputFile + "/" + outputFileName);
            outputStream.write(outputBytes);
            outputStream.close();
    }

    //сместить строки в другую сторону
    private static void invShiftRows(byte[][] state) {
        byte[] t = new byte[4];
        for (int r = 1; r < 4; r++) {
            for (int c = 0; c < Nb; c++) {
                t[(c + r) % Nb] = state[r][c];
            }
            for (int c = 0; c < Nb; c++) {
                state[r][c] = t[c];
            }
        }
    }

    //Сопоставление с InvBox
    private static void invSubBytes(byte[][] state) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < Nb; c++) {
                state[r][c] = InvSbox[(state[r][c] & 0xf0) >> 4][state[r][c] & 0x0f];
            }
        }
    }

    //функция, обратная mixColumns
    private static void invMixColumns(byte[][] state) {
        for (int c = 0; c < Nb; c++) {
            byte[] column = new byte[4];
            for (int r = 0; r < 4; r++) {
                column[r] = state[r][c];
            }
            state[0][c] = (byte) (mulBy14(column[0]) ^ mulBy11(column[1]) ^ mulBy13(column[2]) ^ mulBy9(column[3]));
            state[1][c] = (byte) (mulBy9(column[0]) ^ mulBy14(column[1]) ^ mulBy11(column[2]) ^ mulBy13(column[3]));
            state[2][c] = (byte) (mulBy13(column[0]) ^ mulBy9(column[1]) ^ mulBy14(column[2]) ^ mulBy11(column[3]));
            state[3][c] = (byte) (mulBy11(column[0]) ^ mulBy13(column[1]) ^ mulBy9(column[2]) ^ mulBy14(column[3]));
        }
    }

    private static byte mulBy9(byte b) {
        return (byte) (mulBy2(mulBy2(mulBy2(b))) ^ b);
    }

    private static byte mulBy11(byte b) {
        return (byte) (mulBy2(mulBy2(mulBy2(b))) ^ mulBy2(b) ^ b);
    }

    private static byte mulBy13(byte b) {
        return (byte) (mulBy2(mulBy2(mulBy2(b))) ^ mulBy2(mulBy2(b)) ^ (byte) (b));
    }

    private static byte mulBy14(byte b) {
        return (byte) (mulBy2(mulBy2(mulBy2(b))) ^ mulBy2(mulBy2(b)) ^ mulBy2(b));
    }

    // функция добавления дополнения
    private static byte[] addPadding(byte[] input) {
        int paddingLength = blockSize - (input.length % blockSize);
        byte paddingByte = (byte) paddingLength;

        byte[] output = new byte[input.length + paddingLength];
        System.arraycopy(input, 0, output, 0, input.length);

        for (int i = input.length; i < output.length; i++) {
            output[i] = paddingByte;
        }

        return output;
    }

    // функция удаления дополнения
    private static byte[] removePadding(byte[] input) {
        int paddingLength = input[input.length - 1];
        byte[] output = new byte[input.length - paddingLength];

        System.arraycopy(input, 0, output, 0, output.length);

        return output;
    }

    //функция для отладки, с помощью нее чекал состояние на каждой итерации
    private static void printState(byte[][] state) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < Nb; c++) {
                System.out.printf("%02x ", state[r][c]);
            }
            System.out.println();
        }
        System.out.println();
    }

}
