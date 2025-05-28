//Author: Ali Rehman NetID: amr567

import java.io.*;
import java.nio.charset.StandardCharsets;

public class scrypt
{
    public static void main(String[] args) {
        if (args.length < 3 || args.length > 4) {
            System.err.println("Usage: scrypt [-D] password plaintext ciphertext");
            System.exit(1);
        }

        boolean debugMode = args[0].equals("-D");
        int argOffset = debugMode ? 1 : 0;

        String password = args[argOffset];
        String inputFile = args[argOffset + 1];
        String outputFile = args[argOffset + 2];

        encryptOrDecrypt(password, inputFile, outputFile, debugMode);
    }

    private static void encryptOrDecrypt(String password, String inputFile, String outputFile, boolean debug) {
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        long seed = generateSeed(passwordBytes);
        int key = (int) seed & 0xFF;

        if (debug) {
            System.out.println("Debug Mode ON");
            System.out.println("Using seed: " + seed);
        }

        try (InputStream inputStream = new BufferedInputStream(new FileInputStream(inputFile));
             OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFile))) {

            int byteRead;
            while ((byteRead = inputStream.read()) != -1) {
                key = (1103515245 * key + 12345) & 0xFF;
                if (debug) {
                    System.out.printf("XOR Byte: 0x%02X -> 0x%02X%n", byteRead, byteRead ^ key);
                }
                outputStream.write(byteRead ^ key);
            }
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static long generateSeed(byte[] data) {
        long hash = 0;
        for (byte b : data) {
            hash = (b & 0xFF) + (hash << 6) + (hash << 16) - hash;
        }
        return hash;
    }
}