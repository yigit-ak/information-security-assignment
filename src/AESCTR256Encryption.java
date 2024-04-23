import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;

public class AESCTR256Encryption {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        String inputFile = "image_to_encrypt.jpg"; // Path to input image file
        String encryptedFile = "encrypted_ctr256.jpg"; // Path to store encrypted image file
        String decryptedFile = "decrypted_ctr256.jpg"; // Path to store decrypted image file

        generate_symmetric_keys symKeys = new generate_symmetric_keys();
        SecretKey key = symKeys.getK2();


        try {
            // Encrypt the image file
            encryptCTR(inputFile, encryptedFile, key);

            // Decrypt the encrypted image file
            decryptCTR(encryptedFile, decryptedFile, key);

            System.out.println("Encryption and decryption completed successfully.");
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
            byte[] finalBytes = cipher.doFinal();
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
            byte[] finalBytes = cipher.doFinal();
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
