import javax.crypto.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.spec.SecretKeySpec;

public class generate_symmetric_keys {
    private static SecretKey k1;
    private static SecretKey k2;
    private static SecretKey k3;

    public generate_symmetric_keys(){
        try {
            k1 = generateSymmetricKey("AES", 128);
            k2 = generateSymmetricKey("AES", 256);

            // Task a: Generate K3
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(256);
            KeyPair kbMinus = keyPairGenerator.generateKeyPair(); // KB-
            KeyPair kcPlus = keyPairGenerator.generateKeyPair(); // KC+
            k3 = generateSharedSecretKey(kcPlus.getPublic(), kbMinus.getPrivate());
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            generate_symmetric_keys keys = new generate_symmetric_keys();
            SecretKey k1 = keys.getK1();
            SecretKey k2 = keys.getK2();

            // Print values of K1 and K2
            System.out.println("Generated Symmetric Keys:");
            System.out.println("K1 (128-bit key): " + encodeToString(k1.getEncoded()));
            System.out.println("K2 (256-bit key): " + encodeToString(k2.getEncoded()));

            // Task a: Encrypt and Decrypt K1 and K2 with RSA
            KeyPair rsaKeyPair = generateKeyPair("RSA", 1024);

            // Encrypt K1 with RSA public key
            byte[] encryptedK1 = encryptWithRSA(k1.getEncoded(), rsaKeyPair.getPublic());

            // Decrypt K1 with RSA private key
            byte[] decryptedK1 = decryptWithRSA(encryptedK1, rsaKeyPair.getPrivate());

            // Print results
            System.out.println("\nEncrypted K1 with RSA:");
            System.out.println(encodeToString(encryptedK1));
            System.out.println("\nDecrypted K1 with RSA:");
            System.out.println(encodeToString(decryptedK1));

            // Encrypt K2 with RSA public key
            byte[] encryptedK2 = encryptWithRSA(k2.getEncoded(), rsaKeyPair.getPublic());

            // Decrypt K2 with RSA private key
            byte[] decryptedK2 = decryptWithRSA(encryptedK2, rsaKeyPair.getPrivate());

            // Print results
            System.out.println("\nEncrypted K2 with RSA:");
            System.out.println(encodeToString(encryptedK2));
            System.out.println("\nDecrypted K2 with RSA:");
            System.out.println(encodeToString(decryptedK2));

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(256);
            KeyPair kbMinus = keyPairGenerator.generateKeyPair(); // KB-
            KeyPair kcPlus = keyPairGenerator.generateKeyPair(); // KC+

            SecretKey k3 = keys.getK3();
            // Generate symmetric key using KB+ and KC-
            SecretKey k4 = generateSharedSecretKey(kbMinus.getPublic(), kcPlus.getPrivate());

            // Verify if K3 and K4 are the same
            boolean keysMatch = k3.equals(k4);
            System.out.println("\nGenerated Symmetric Key using ECDH (K3): " + encodeToString(k3.getEncoded()));
            System.out.println("\nGenerated Symmetric Key using ECDH (K4): " + encodeToString(k4.getEncoded()));
            System.out.println("\n Are K3 and K4 the same? -> " + keysMatch);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    private static SecretKey generateSymmetricKey(String algorithm, int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    private static KeyPair generateKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] encryptWithRSA(byte[] data, java.security.PublicKey publicKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    private static byte[] decryptWithRSA(byte[] data, java.security.PrivateKey privateKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    private static SecretKey generateSharedSecretKey(PublicKey publicKey, PrivateKey privateKey)
            throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        return new SecretKeySpec(sharedSecret, 0, 32, "AES");
    }

    private static String encodeToString(byte[] bytes) {
        return java.util.Base64.getEncoder().encodeToString(bytes);
    }
    public SecretKey getK1() {
        return k1;
    }

    public SecretKey getK2() {
        return k2;
    }

    public SecretKey getK3() {
        return k3;
    }
}
