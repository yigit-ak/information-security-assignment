import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;

public class Aes256BitCtrEncryptor {
    public void perform() {
        String inputFile = "resources/image_to_encrypt.jpg"; // Path to input image file
        String encryptedFile = "outputs/encrypted_ctr256.jpg"; // Path to store encrypted image file
        String decryptedFile = "outputs/decrypted_ctr256.jpg"; // Path to store decrypted image file

        try {
            // Encrypt the image file
            encryptCTR(inputFile, encryptedFile, Keys.symmetricKey3);

            // Decrypt the encrypted image file
            decryptCTR(encryptedFile, decryptedFile, Keys.symmetricKey3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Encrypt file using AES in CTR mode
    private static void encryptCTR(String inputFile, String outputFile, SecretKey key) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        try (InputStream in = new FileInputStream(inputFile);
             OutputStream out = new FileOutputStream(outputFile)) {

            // Generate a random IV (nonce)
            SecureRandom random = new SecureRandom();
            byte[] ivBytes = new byte[16];
            random.nextBytes(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            // Initialize AES cipher in CTR mode
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            // Write IV to the beginning of the encrypted file
            out.write(ivBytes);

            // Encrypt the file
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                byte[] encryptedBytes = cipher.update(buffer, 0, bytesRead);
                out.write(encryptedBytes);
            }

            long startTime = System.nanoTime();
            byte[] finalBytes = cipher.doFinal();
            long endTime = System.nanoTime();

            long encryptionTimeNano = endTime - startTime;
            double encryptionTimeMillis = encryptionTimeNano / 1_000_000.0;
            System.out.println("Encryption Time (milliseconds): " + encryptionTimeMillis);

            out.write(finalBytes);
        }
    }

    // Decrypt file using AES in CTR mode
    private static void decryptCTR(String inputFile, String outputFile, SecretKey key) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        try (InputStream in = new FileInputStream(inputFile);
             OutputStream out = new FileOutputStream(outputFile)) {

            // Read IV from the beginning of the encrypted file
            byte[] ivBytes = new byte[16];
            in.read(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            // Initialize AES cipher in CTR mode
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);


            // Decrypt the file
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                byte[] decryptedBytes = cipher.update(buffer, 0, bytesRead);
                out.write(decryptedBytes);
            }
            long startTime = System.nanoTime();
            byte[] finalBytes = cipher.doFinal();
            long endTime = System.nanoTime();

            long decryptionTimeNano = endTime - startTime;
            double decryptionTimeMillis = decryptionTimeNano / 1_000_000.0;
            System.out.println("Decryption Time (milliseconds): " + decryptionTimeMillis);

            out.write(finalBytes);
        } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
