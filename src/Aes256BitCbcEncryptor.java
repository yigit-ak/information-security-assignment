import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.util.Base64;

public class Aes256BitCbcEncryptor {
    public void perform() {
        try {
            // Load the original image file
            File originalFile = new File("resources/image_to_encrypt.jpg");
            FileInputStream originalInputStream = new FileInputStream(originalFile);
            byte[] originalData = new byte[(int) originalFile.length()];
            originalInputStream.read(originalData);
            originalInputStream.close();

            byte[] iv = generateIV();
            System.out.println("\nIV: " + Base64.getEncoder().encodeToString(iv));
            Long startTime = System.nanoTime();
            byte[] encrypted256 = encryptAES_CBC(originalData, Keys.symmetricKey2, iv,"AES/CBC/PKCS5Padding" );
            long endTime = System.nanoTime();

            long encryptionTimeNano = endTime - startTime;

            saveToFile("encrypted_cbc256.jpg", encrypted256);

            double encryptionTimeMillis = encryptionTimeNano / 1_000_000.0;
            System.out.println("Encryption Time (milliseconds): " + encryptionTimeMillis);

            startTime = System.nanoTime();
            byte[] decrypted256 = decryptAES_CBC(encrypted256, Keys.symmetricKey2,iv,"AES/CBC/PKCS5Padding");
            endTime = System.nanoTime();

            long decryptionTimeNano = endTime - startTime;

            double decryptionTimeMillis = decryptionTimeNano / 1_000_000.0;
            System.out.println("Decryption Time (milliseconds): " + decryptionTimeMillis);

            saveToFile("decrypted_cbc256.jpg", decrypted256);

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
        byte[] iv = new byte[16]; // (128 bits)
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
