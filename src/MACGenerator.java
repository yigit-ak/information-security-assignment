import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class MACGenerator {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        // Generate symmetric keys K1 (128-bit) and K2 (256-bit)
        SecretKey key1 = generateSymmetricKey(128);

        SecretKey key2 = generateSymmetricKey(256);
        String key2String = key2.toString();
        byte[] key2Bytes = key2String.getBytes();

        // Text message
        String message = "This is a text message generated for information security assignment.";

        // Generate HMAC-SHA256 code using K1
        byte[] mac1 = generateHMACSHA256(key1, message.getBytes());

        // Print the MAC for K1
        System.out.println("HMAC-SHA256 for text message using K1: " + Base64.getEncoder().encodeToString(mac1));

        byte[] newKeyBytes = generateNewKey(key2Bytes, message.getBytes());

        // Print the new key 
        System.out.println("New Key (256-bit) from K2: " + Base64.getEncoder().encodeToString(newKeyBytes));

        // Print the new key (byte array representation)
        System.out.print("New Key (256-bit) from K2: ");
        for (byte b : newKeyBytes) {
            System.out.printf("%02X", b); // Print each byte as a hexadecimal value
        }
        System.out.println();


    }

    // Generate a symmetric key (K1 or K2)
    private static SecretKey generateSymmetricKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize); // 128-bit key size for K1, 256-bit key size for K2
        return keyGen.generateKey();
    }

    // Generate HMAC-SHA256 code
    private static byte[] generateHMACSHA256(SecretKey key, byte[] message) throws NoSuchAlgorithmException {
        try {
            Mac hmacSha256 = Mac.getInstance("HmacSHA256");
            hmacSha256.init(key);
            return hmacSha256.doFinal(message);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // Generate a new 256-bit key using HMAC-SHA256 with K2
    private static byte[] generateNewKey(byte[] key, byte[] message) throws NoSuchAlgorithmException {
        try {
            Mac hmacSha256 = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
            hmacSha256.init(keySpec);
            return hmacSha256.doFinal(message);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
