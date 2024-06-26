import java.security.*;
import java.util.Base64;

public class PublicPrivateKeyGenerator {
    private PublicKey rsaPublicKey;
    private PrivateKey rsaPrivateKey;
    private PublicKey ecdhPublicKey1;
    private PrivateKey ecdhPrivateKey1;
    private PublicKey ecdhPublicKey2;
    private PrivateKey ecdhPrivateKey2;

    public PublicPrivateKeyGenerator() {
    }

    public void generateKeys() {
        try {
            // Generate RSA Key Pair
            KeyPairGenerator rsaKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
            rsaKeyPairGenerator.initialize(1024);
            KeyPair rsaKeyPair = rsaKeyPairGenerator.generateKeyPair();

            rsaPublicKey = rsaKeyPair.getPublic();
            rsaPrivateKey = rsaKeyPair.getPrivate();

            // Generate Elliptic-Curve Diffie Helman Key Pair 1
            KeyPairGenerator ecdhKeyPairGenerator1 = KeyPairGenerator.getInstance("EC");
            ecdhKeyPairGenerator1.initialize(256);
            KeyPair ecdhKeyPair1 = ecdhKeyPairGenerator1.generateKeyPair();

            ecdhPublicKey1 = ecdhKeyPair1.getPublic();
            ecdhPrivateKey1 = ecdhKeyPair1.getPrivate();

            // Generate Elliptic-Curve Diffie Helman Key Pair 2
            KeyPairGenerator ecdhKeyPairGenerator2 = KeyPairGenerator.getInstance("EC");
            ecdhKeyPairGenerator2.initialize(256);
            KeyPair ecdhKeyPair2 = ecdhKeyPairGenerator2.generateKeyPair();

            ecdhPublicKey2 = ecdhKeyPair2.getPublic();
            ecdhPrivateKey2 = ecdhKeyPair2.getPrivate();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void printKeys() {
        System.out.println("Generated Keys:");
        System.out.println("RSA Public Key (KA+): " + Base64.getEncoder().encodeToString(rsaPublicKey.getEncoded()));
        System.out.println("\nRSA Private Key (KA-): " + Base64.getEncoder().encodeToString(rsaPrivateKey.getEncoded()));
        System.out.println("\nEC Key Pair 1 (KB+): " + Base64.getEncoder().encodeToString(ecdhPublicKey1.getEncoded()));
        System.out.println("\nEC Private Key 1 (KB-): " + Base64.getEncoder().encodeToString(ecdhPrivateKey1.getEncoded()));
        System.out.println("\nEC Key Pair 2 (KC+): " + Base64.getEncoder().encodeToString(ecdhPublicKey2.getEncoded()));
        System.out.println("\nEC Private Key 2 (KC-): " + Base64.getEncoder().encodeToString(ecdhPrivateKey2.getEncoded()));
    }

    public PublicKey getRsaPublicKey() {
        return rsaPublicKey;
    }

    public PrivateKey getRsaPrivateKey() {
        return rsaPrivateKey;
    }

    public PublicKey getEcdhPublicKey1() {
        return ecdhPublicKey1;
    }

    public PrivateKey getEcdhPrivateKey1() {
        return ecdhPrivateKey1;
    }

    public PublicKey getEcdhPublicKey2() {
        return ecdhPublicKey2;
    }

    public PrivateKey getEcdhPrivateKey2() {
        return ecdhPrivateKey2;
    }
}
