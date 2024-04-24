import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class SymmetricKeyGenerator {
    private SecretKey k1;
    private SecretKey k2;
    private SecretKey k3;

    public SymmetricKeyGenerator() {
    }

    public void generateKeys() {
        try {
            this.k1 = generateSymmetricKey("AES", 128);
            this.k2 = generateSymmetricKey("AES", 256);

            // Task a: Generate K3
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(256);
            this.k3 = generateSharedSecretKey(Keys.publicKeyC, Keys.privateKeyB);

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public void validateEncryptionOfKeys() {
        try {
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

            // Generate symmetric key using KB+ and KC-
            SecretKey k4 = generateSharedSecretKey(Keys.publicKeyB, Keys.privateKeyC);

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

    private SecretKey generateSymmetricKey(String algorithm, int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    private KeyPair generateKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    private byte[] encryptWithRSA(byte[] data, java.security.PublicKey publicKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    private byte[] decryptWithRSA(byte[] data, java.security.PrivateKey privateKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    private SecretKey generateSharedSecretKey(PublicKey publicKey, PrivateKey privateKey)
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
