//Author: Ali Rehman NetID: amr567

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class feistel{

    private static final int BLOCK_SIZE = 16;
    private static final int ROUNDS = 10;
    private static final long MULTIPLIER = 1103515245L;
    private static final long INCREMENT = 12345L;

    public static void main(String[] args) {
        if (args.length != 4) {
            System.out.println("Usage:");
            System.out.println("  Encrypt: java FeistelCipher -e <password> <inputFile> <outputFile>");
            System.out.println("  Decrypt: java FeistelCipher -d <password> <inputFile> <outputFile>");
            return;
        }

        String operation = args[0];
        String password = args[1];
        String inputFilePath = args[2];
        String outputFilePath = args[3];

        try {
            if ("-e".equals(operation)) {
                encrypt(password, inputFilePath, outputFilePath);
            } else if ("-d".equals(operation)) {
                decrypt(password, inputFilePath, outputFilePath);
            } else {
                System.out.println("Error: Invalid operation. Use '-e' to encrypt or '-d' to decrypt.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void encrypt(String password, String inputFilePath, String outputFilePath) throws IOException {
        long initialKey = generateKey(password);
        long[] roundKeys = generateRoundKeys(initialKey);

        byte[] plainText = readFile(inputFilePath);
        byte[] paddedData = applyPadding(plainText);

        ByteArrayOutputStream encryptedDataStream = new ByteArrayOutputStream();

        for (int i = 0; i < paddedData.length; i += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(paddedData, i, i + BLOCK_SIZE);
            byte[] encryptedBlock = encryptBlock(block, roundKeys);
            encryptedDataStream.write(encryptedBlock);
        }
        writeFile(outputFilePath, encryptedDataStream.toByteArray());
    }

    private static void decrypt(String password, String inputFilePath, String outputFilePath) throws IOException {
        long initialKey = generateKey(password);
        long[] roundKeys = generateRoundKeys(initialKey);

        byte[] cipherText = readFile(inputFilePath);
        ByteArrayOutputStream decryptedDataStream = new ByteArrayOutputStream();

        for (int i = 0; i < cipherText.length; i += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(cipherText, i, i + BLOCK_SIZE);
            byte[] decryptedBlock = decryptBlock(block, roundKeys);
            decryptedDataStream.write(decryptedBlock);
        }

        byte[] decryptedWithPadding = decryptedDataStream.toByteArray();
        byte[] originalPlainText = removePadding(decryptedWithPadding);
        writeFile(outputFilePath, originalPlainText);
    }

    private static byte[] encryptBlock(byte[] block, long[] roundKeys) {
        long leftPart = convertToLong(block, 0);
        long rightPart = convertToLong(block, 8);

        for (int i = 0; i < ROUNDS; i++) {
            long temp = rightPart;
            rightPart = leftPart ^ feistelFunction(rightPart, roundKeys[i]);
            leftPart = temp;
        }
        return mergeLongs(leftPart, rightPart);
    }

    private static byte[] decryptBlock(byte[] block, long[] roundKeys) {
        long leftPart = convertToLong(block, 0);
        long rightPart = convertToLong(block, 8);

        for (int i = ROUNDS - 1; i >= 0; i--) {
            long temp = leftPart;
            leftPart = rightPart ^ feistelFunction(leftPart, roundKeys[i]);
            rightPart = temp;
        }
        return mergeLongs(leftPart, rightPart);
    }

    private static long feistelFunction(long value, long roundKey) {
        long mixedValue = (value ^ roundKey) * 0xa3b2c1L;
        return (mixedValue >>> 23) | (mixedValue << 41);
    }

    private static long[] generateRoundKeys(long seed) {
        long[] roundKeys = new long[ROUNDS];
        roundKeys[0] = seed;
        for (int i = 1; i < ROUNDS; i++) {
            roundKeys[i] = (roundKeys[i - 1] * MULTIPLIER + INCREMENT) & 0xffffffffffffffffL;
        }
        return roundKeys;
    }

    private static long generateKey(String input) {
        long hashValue = 0;
        for (char c : input.toCharArray()) {
            hashValue = c + (hashValue << 6) + (hashValue << 16) - hashValue;
        }
        return hashValue;
    }

    private static byte[] readFile(String filePath) throws IOException {
        File file = new File(filePath);
        byte[] fileContent = new byte[(int) file.length()];
        try (FileInputStream inputStream = new FileInputStream(file)) {
            if (inputStream.read(fileContent) != fileContent.length) {
                throw new IOException("Error reading file completely: " + filePath);
            }
        }
        return fileContent;
    }

    private static void writeFile(String filePath, byte[] data) throws IOException {
        try (FileOutputStream outputStream = new FileOutputStream(filePath)) {
            outputStream.write(data);
        }
    }

    private static byte[] applyPadding(byte[] data) {
        int paddingLength = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte[] paddedData = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, paddedData, 0, data.length);
        Arrays.fill(paddedData, data.length, paddedData.length, (byte) paddingLength);
        return paddedData;
    }

    private static byte[] removePadding(byte[] data) {
        int paddingLength = data[data.length - 1] & 0xFF;
        if (paddingLength < 1 || paddingLength > BLOCK_SIZE || paddingLength > data.length) {
            throw new IllegalArgumentException("Invalid padding detected: " + paddingLength);
        }
        for (int i = data.length - paddingLength; i < data.length; i++) {
            if (data[i] != (byte) paddingLength) {
                throw new IllegalArgumentException("Padding corruption detected.");
            }
        }
        return Arrays.copyOfRange(data, 0, data.length - paddingLength);
    }

    private static long convertToLong(byte[] data, int offset) {
        return ByteBuffer.wrap(data, offset, 8).order(ByteOrder.BIG_ENDIAN).getLong();
    }

    private static byte[] mergeLongs(long left, long right) {
        ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE).order(ByteOrder.BIG_ENDIAN);
        buffer.putLong(left);
        buffer.putLong(right);
        return buffer.array();
    }
}