//Author: Ali Rehman NetID: amr567

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class vcrypt{
    public static void main(String[] args) {
        if (args.length < 4 || (!"-e".equals(args[0]) && !"-d".equals(args[0]))) {
            System.err.println("Usage: vcrypt -e password plaintext ciphertext");
            System.err.println("       vcrypt -d password ciphertext plaintext");
            System.exit(1);
        }
        
        String action = args[0];
        String key = args[1];
        String sourceFile = args[2];
        String destinationFile = args[3];

        try {
            byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
            long keyHash = computeHash(keyBytes);
            
            if ("-e".equals(action)) {
                SecureRandom rng = new SecureRandom();
                byte[] ivArray = new byte[8];
                rng.nextBytes(ivArray);
                long ivValue = ByteBuffer.wrap(ivArray).order(ByteOrder.LITTLE_ENDIAN).getLong();
                long xorSeed = keyHash ^ ivValue;
                
                try (OutputStream output = new BufferedOutputStream(new FileOutputStream(destinationFile))) {
                    output.write(ivArray);
                    transformData(sourceFile, output, xorSeed);
                }
            } else {
                try (InputStream input = new BufferedInputStream(new FileInputStream(sourceFile));
                     OutputStream output = new BufferedOutputStream(new FileOutputStream(destinationFile))) {
                    
                    byte[] ivArray = new byte[8];
                    if (input.read(ivArray) != 8) {
                        throw new IOException("Invalid IV length");
                    }
                    long ivValue = ByteBuffer.wrap(ivArray).order(ByteOrder.LITTLE_ENDIAN).getLong();
                    long xorSeed = keyHash ^ ivValue;
                    processStream(input, output, (int) xorSeed);
                }
            }
        } catch (IOException ex) {
            ex.printStackTrace();
            System.exit(1);
        }
    }

    private static void transformData(String sourceFile, OutputStream output, long seed) throws IOException {
        int state = (byte) seed & 0xFF;
        try (InputStream input = new FileInputStream(sourceFile)) {
            processStream(input, output, state);
        }
    }

    private static void processStream(InputStream input, OutputStream output, int seed) throws IOException {
        int state = seed;
        int readByte;
        while ((readByte = input.read()) != -1) {
            state = (109 * state + 57) % 256;
            output.write(readByte ^ state);
        }
    }

    private static long computeHash(byte[] input) {
        long hashValue = 0;
        for (byte b : input) {
            int temp = b & 0xFF;
            hashValue = temp + (hashValue << 6) + (hashValue << 16) - hashValue;
        }
        return hashValue;
    }
}