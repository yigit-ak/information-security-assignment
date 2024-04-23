import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;

public class aes_cbc_encryption {
    public static void main(String[] args) {
        try {
            generate_symmetric_keys symKeys = new generate_symmetric_keys();
            SecretKey k1 = symKeys.getK1();

            // Load the original image file
            File originalFile = new File("image_to_encrypt.jpg");
            FileInputStream originalInputStream = new FileInputStream(originalFile);
            byte[] originalData = new byte[(int) originalFile.length()];
            originalInputStream.read(originalData);
            originalInputStream.close();

            byte[] iv = generateIV();
            System.out.println("First IV: " + iv);
            Long startTime = System.nanoTime();
            byte[] encrypted128 = encryptAES_CBC(originalData, k1,iv,"AES/CBC/PKCS5Padding" );
            saveToFile("encrypted_cbc128.jpg", encrypted128);
            long endTime = System.nanoTime();
            long encryptionTimeNano = endTime - startTime;

            double encryptionTimeMillis = encryptionTimeNano / 1_000_000.0;
            System.out.println("Encryption Time (milliseconds): " + encryptionTimeMillis);


            byte[] decrypted128 = decryptAES_CBC(encrypted128, k1,iv,"AES/CBC/PKCS5Padding");
            saveToFile("decrypted_cbc128.jpg", decrypted128);

            iv = generateIV();
            System.out.println("Second IV: " + iv);
            byte[] encrypted128_2 = encryptAES_CBC(originalData, k1, iv,"AES/CBC/PKCS5Padding");
            byte[] decrypted128_2 = decryptAES_CBC(encrypted128_2, k1, iv, "AES/CBC/PKCS5Padding");

            // Verify that the decrypted data matches the original files
            boolean match128 = compareByteArrays(originalData, decrypted128);
            boolean changed = !compareByteArrays(encrypted128, encrypted128_2);

            System.out.println("Decrypted data matches original data (128-bit): " + match128);
            System.out.println("Ciphertext 1: " + encrypted128);
            System.out.println("Ciphertext 2: " + encrypted128_2 );
            System.out.println("Does the ciphertext change when the IV changed? : " + changed);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Encrypt data using AES in CBC mode
    private static byte[] encryptAES_CBC(byte[] data, SecretKey key, byte[] iv, String transformation) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(transformation);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);

        // Perform encryption
        return cipher.doFinal(data);
    }

    // Decrypt data using AES in CBC mode
    private static byte[] decryptAES_CBC(byte[] data, SecretKey key, byte[] iv, String transformation) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(transformation);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);

        // Perform decryption
        return cipher.doFinal(data);
    }


    // Save data to a file
    private static void saveToFile(String fileName, byte[] data) throws IOException {
        FileOutputStream outputStream = new FileOutputStream(fileName);
        outputStream.write(data);
        outputStream.close();
    }

    // Compare byte arrays to check for equality
    private static boolean compareByteArrays(byte[] arr1, byte[] arr2) {
        if (arr1.length != arr2.length) {
            return false;
        }
        for (int i = 0; i < arr1.length; i++) {
            if (arr1[i] != arr2[i]) {
                return false;
            }
        }
        return true;
    }
    private static byte[] generateIV() {
        byte[] iv = new byte[16]; // For AES, IV size is typically 16 bytes (128 bits)
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
