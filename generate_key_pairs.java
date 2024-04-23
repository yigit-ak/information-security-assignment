import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class generate_key_pairs {
    private PublicKey rsaPublicKey;
    private PrivateKey rsaPrivateKey;
    private PublicKey ecdhPublicKey1;
    private PrivateKey ecdhPrivateKey1;
    private PublicKey ecdhPublicKey2;
    private PrivateKey ecdhPrivateKey2;

    public generate_key_pairs() throws Exception {
        // Generate RSA Key Pair
        KeyPairGenerator rsaKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
        rsaKeyPairGenerator.initialize(1024); // You can adjust the key size as needed
        KeyPair rsaKeyPair = rsaKeyPairGenerator.generateKeyPair();

        // Generate Elliptic-Curve Diffie Helman Key Pair 1
        KeyPairGenerator ecdhKeyPairGenerator1 = KeyPairGenerator.getInstance("EC");
        ecdhKeyPairGenerator1.initialize(256); // You can choose different curve sizes
        KeyPair ecdhKeyPair1 = ecdhKeyPairGenerator1.generateKeyPair();

        // Generate Elliptic-Curve Diffie Helman Key Pair 2
        KeyPairGenerator ecdhKeyPairGenerator2 = KeyPairGenerator.getInstance("EC");
        ecdhKeyPairGenerator2.initialize(256); // You can choose different curve sizes
        KeyPair ecdhKeyPair2 = ecdhKeyPairGenerator2.generateKeyPair();

        // Assign keys
        rsaPublicKey = rsaKeyPair.getPublic();
        rsaPrivateKey = rsaKeyPair.getPrivate();

        ecdhPublicKey1 = ecdhKeyPair1.getPublic();
        ecdhPrivateKey1 = ecdhKeyPair1.getPrivate();

        ecdhPublicKey2 = ecdhKeyPair2.getPublic();
        ecdhPrivateKey2 = ecdhKeyPair2.getPrivate();
    }

    public static void main(String[] args) {
        try {
            generate_key_pairs keys = new generate_key_pairs();
            keys.printKeys();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void printKeys() {
        System.out.println("Generated Keys:");
        System.out.println("RSA Public Key (KA+): " + Base64.getEncoder().encodeToString(rsaPublicKey.getEncoded()));
        System.out.println("\nRSA Private Key (KA-): " + Base64.getEncoder().encodeToString(rsaPrivateKey.getEncoded()));
        System.out.println("\nEC Key Pair 1 (KB+): " + Base64.getEncoder().encodeToString(ecdhPublicKey1.getEncoded()));
        System.out.println("\nEC Private Key 1 (KB-): " + Base64.getEncoder().encodeToString(ecdhPrivateKey1.getEncoded()));
        System.out.println("\nEC Key Pair 2 (KC+): " + Base64.getEncoder().encodeToString(ecdhPublicKey2.getEncoded()));
        System.out.println("\nEC Private Key 2 (KC-): " + Base64.getEncoder().encodeToString(ecdhPrivateKey2.getEncoded()));
    }
}
