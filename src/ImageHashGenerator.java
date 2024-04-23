import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class ImageHashGenerator {
    private final String imagePath = "resources/image_to_encrypt.jpg";
    private final String HASHING_METHOD = "SHA-256";
    private final int MAX_IMAGE_SIZE = 1_000_000; // in bytes
    private byte[] hash;

    public ImageHashGenerator() {
    }

    public void generateImageHashValue() {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance(HASHING_METHOD);
        } catch (NoSuchAlgorithmException e) {
            System.out.println(HASHING_METHOD + " algorithm not found");
        }

        // image to byte array
        byte[] buffer = new byte[MAX_IMAGE_SIZE];
        int bytesRead = 0;

        try (FileInputStream inputStream = new FileInputStream(imagePath)) {
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        this.hash = digest.digest();
    }

    public void printHash() {
        System.out.println("\nHash of the image: " + Base64.getEncoder().encodeToString(hash));
    }

    public void generateDigitalSignature() {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, Main.privateKeyA);
            byte[] signedHash = cipher.doFinal(this.hash);

            System.out.println("\nDigital signature of hash (encrypted with KA-): "
                    + Base64.getEncoder().encodeToString(signedHash));

            cipher.init(Cipher.DECRYPT_MODE, Main.publicKeyA);
            byte[] decryptedHash = cipher.doFinal(signedHash);

            System.out.println("\nDecryption of digital signature with KA+: "
            + Base64.getEncoder().encodeToString(decryptedHash));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
