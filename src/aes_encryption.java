import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;

public class aes_encryption {
    public static void main(String[] args) {
        try {
            generate_symmetric_keys symKeys = new generate_symmetric_keys();
            SecretKey k1 = symKeys.getK1();
            SecretKey k2 = symKeys.getK2();
            SecretKey k3 = symKeys.getK3();

            if (k1 == null || k2 == null || k3 == null) {
                System.out.println("Failed to retrieve symmetric keys.");
                return;
            }
            // Load the image file
            File inputFile = new File("image_to_encrypt.jpg");
            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);
            inputStream.close();



            // Encrypt the image using AES in CBC mode with a 128-bit key
            byte[] encrypted128 = encryptAES_CBC(inputBytes, k1, "AES/CBC/PKCS5Padding");

            // Encrypt the image using AES in CBC mode with a 256-bit key
            byte[] encrypted256_CBC = encryptAES_CBC(inputBytes, k2, "AES/CBC/PKCS5Padding");

            // Encrypt the image using AES in CTR mode with a 256-bit key
            byte[] encrypted256_CTR = encryptAES_CTR(inputBytes, k3, "AES/CTR/NoPadding");

            // Save the encrypted images
            saveToFile("image_encrypted_128_CBC.jpg", encrypted128);
            saveToFile("image_encrypted_256_CBC.jpg", encrypted256_CBC);
            saveToFile("image_encrypted_256_CTR.jpg", encrypted256_CTR);

            System.out.println("Encryption completed successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Generate a symmetric key
    private static SecretKey generateSymmetricKey(String algorithm, int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    // Encrypt data using AES in CBC mode
    private static byte[] encryptAES_CBC(byte[] data, SecretKey key, String transformation) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // Encrypt data using AES in CTR mode
    private static byte[] encryptAES_CTR(byte[] data, SecretKey key, String transformation) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(transformation);
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        random.nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encryptedData = cipher.doFinal(data);
        byte[] encryptedWithIV = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, encryptedWithIV, 0, iv.length);
        System.arraycopy(encryptedData, 0, encryptedWithIV, iv.length, encryptedData.length);
        return encryptedWithIV;
    }

    // Save data to a file
    private static void saveToFile(String fileName, byte[] data) throws IOException {
        FileOutputStream outputStream = new FileOutputStream(fileName);
        outputStream.write(data);
        outputStream.close();
    }
}
