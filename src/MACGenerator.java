import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class MACGenerator {
    public void perform()  {
        // Text message
        String message = "\n\nWe wrote this text message for our information security homework.";
        System.out.println("Message: " + message);

        // Generate HMAC-SHA256 code using K1
        byte[] mac1 = null;
        try {
            mac1 = generateHMACSHA256(Keys.symmetricKey1, message.getBytes());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // Print the MAC for K1
        System.out.println("HMAC-SHA256 for text message using K1: " + Base64.getEncoder().encodeToString(mac1));

        byte[] newKeyBytes = generateNewKey(Keys.symmetricKey2, message.getBytes());

        // Print the new key
        System.out.println("New Key (256-bit) from K2 as string: " + Base64.getEncoder().encodeToString(newKeyBytes));

        // Print the new key (byte array representation)
        System.out.print("New Key (256-bit) from K2 as hex: ");
        for (byte b : newKeyBytes) {
            System.out.printf("%02X", b); // Print each byte as a hexadecimal value
        }
        System.out.println();
    }

    // Generate HMAC-SHA256 code
    private static byte[] generateHMACSHA256(SecretKey key, byte[] message) {
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
    private static byte[] generateNewKey(SecretKey key, byte[] message) {
        try {
            byte[] keyBytes = key.getEncoded();
            Mac hmacSha256 = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
            hmacSha256.init(keySpec);
            return hmacSha256.doFinal(message);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
