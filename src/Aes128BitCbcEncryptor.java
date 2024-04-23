import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.util.Base64;

public class Aes128BitCbcEncryptor {
    public void perform() {
        try {
            // Load the original image file
            File originalFile = new File("resources/image_to_encrypt.jpg");
            FileInputStream originalInputStream = new FileInputStream(originalFile);
            byte[] originalData = new byte[(int) originalFile.length()];
            originalInputStream.read(originalData);
            originalInputStream.close();

            byte[] iv = generateIV();
            System.out.println("\nFirst IV: " + Base64.getEncoder().encodeToString(iv));
            Long startTime = System.nanoTime();
            byte[] encrypted128 = encryptAES_CBC(originalData, Keys.symmetricKey1, iv,"AES/CBC/PKCS5Padding" );
            long endTime = System.nanoTime();

            long encryptionTimeNano = endTime - startTime;

            saveToFile("encrypted_cbc128.jpg", encrypted128);

            double encryptionTimeMillis = encryptionTimeNano / 1_000_000.0;
            System.out.println("Encryption Time (milliseconds): " + encryptionTimeMillis);

            startTime = System.nanoTime();
            byte[] decrypted128 = decryptAES_CBC(encrypted128, Keys.symmetricKey1,iv,"AES/CBC/PKCS5Padding");
            endTime = System.nanoTime();

            long decryptionTimeNano = endTime - startTime;

            double decryptionTimeMillis = decryptionTimeNano / 1_000_000.0;
            System.out.println("Decryption Time (milliseconds): " + decryptionTimeMillis);

            saveToFile("decrypted_cbc128.jpg", decrypted128);

            iv = generateIV();
            System.out.println("Second IV: " + Base64.getEncoder().encodeToString(iv));
            byte[] encrypted128_2 = encryptAES_CBC(originalData, Keys.symmetricKey1, iv,"AES/CBC/PKCS5Padding");
            byte[] decrypted128_2 = decryptAES_CBC(encrypted128_2, Keys.symmetricKey1, iv, "AES/CBC/PKCS5Padding");

            // Verify that the decrypted data matches the original files
            boolean match128 = compareByteArrays(originalData, decrypted128);
            boolean changed = !compareByteArrays(encrypted128, encrypted128_2);

            System.out.println("Decrypted data matches original data (128-bit): " + match128);

            saveToFile("encrypted_cbc128_vi1.jpg", Base64.getEncoder().encodeToString(encrypted128));
            saveToFile("encrypted_cbc128_vi2.jpg", Base64.getEncoder().encodeToString(encrypted128_2));

            System.out.println("Does the ciphertext change when the IV changed? : " + changed);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Encrypt data using AES in CBC mode
    private byte[] encryptAES_CBC(byte[] data, SecretKey key, byte[] iv, String transformation) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(transformation);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);

        // Perform encryption
        return cipher.doFinal(data);
    }

    // Decrypt data using AES in CBC mode
    private byte[] decryptAES_CBC(byte[] data, SecretKey key, byte[] iv, String transformation) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(transformation);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);

        // Perform decryption
        return cipher.doFinal(data);
    }


    // Save data to a file
    private void saveToFile(String fileName, byte[] data) throws IOException {
        FileOutputStream outputStream = new FileOutputStream("outputs/"+fileName);
        outputStream.write(data);
        outputStream.close();
    }

    private void saveToFile(String fileName, String data) throws IOException {
        FileWriter writer = new FileWriter("outputs/"+fileName);
        writer.write(data);
        writer.close();
    }

    // Compare byte arrays to check for equality
    private boolean compareByteArrays(byte[] arr1, byte[] arr2) {
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
    private byte[] generateIV() {
        byte[] iv = new byte[16]; // For AES, IV size is typically 16 bytes (128 bits)
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
