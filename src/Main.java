public class Main {
    public static void main(String[] args) {
        generatePublicPrivateKeyPairs();
        generateSymmetricKeys();
        generateDigitalSignatureForImage();
        performAesEncryption();
        performMessageAuthenticationForText();
    }

    private static void generatePublicPrivateKeyPairs() {
        PublicPrivateKeyGenerator publicPrivateKeyGenerator = new PublicPrivateKeyGenerator();
        publicPrivateKeyGenerator.generateKeys();

        // key pair created using RSA
        Keys.publicKeyA = publicPrivateKeyGenerator.getRsaPublicKey();
        Keys.privateKeyA = publicPrivateKeyGenerator.getRsaPrivateKey();

        // key pairs created using ecliptic curve
        Keys.publicKeyB = publicPrivateKeyGenerator.getEcdhPublicKey1();
        Keys.privateKeyB = publicPrivateKeyGenerator.getEcdhPrivateKey1();
        Keys.publicKeyC = publicPrivateKeyGenerator.getEcdhPublicKey2();
        Keys.privateKeyC = publicPrivateKeyGenerator.getEcdhPrivateKey2();

        publicPrivateKeyGenerator.printKeys();
    }

    private static void generateSymmetricKeys() {
        // symmetric key generation
        SymmetricKeyGenerator symmetricKeyGenerator = new SymmetricKeyGenerator();
        symmetricKeyGenerator.generateKeys();
        symmetricKeyGenerator.validateEncryptionOfKeys();

        // symmetric keys to be created using derivation function
        Keys.symmetricKey1 = symmetricKeyGenerator.getK1();
        Keys.symmetricKey2 = symmetricKeyGenerator.getK2();

        // symmetric key to be created using ecliptic key
        Keys.symmetricKey3 = symmetricKeyGenerator.getK3();
    }


    private static void generateDigitalSignatureForImage() {
        ImageHashGenerator imageHashGenerator = new ImageHashGenerator();
        imageHashGenerator.generateImageHashValue();
        imageHashGenerator.printHash();
        imageHashGenerator.generateDigitalSignature();
    }

    private static void performAesEncryption() {
        System.out.println("\nAES (128 bit key) in CBC mode");
        Aes128BitCbcEncryptor aes128BitCbc = new Aes128BitCbcEncryptor();
        aes128BitCbc.perform();

        System.out.println("\nAES (256 bit key) in CBC mode");
        Aes256BitCbcEncryptor aes256BitCbc = new Aes256BitCbcEncryptor();
        aes256BitCbc.perform();

        System.out.println("\nAES (256 bit key) in CTR mode");
        Aes256BitCtrEncryptor aes256BitCtr = new Aes256BitCtrEncryptor();
        aes256BitCtr.perform();
    }


    private static void performMessageAuthenticationForText() {
        MACGenerator mac = new MACGenerator();
        mac.perform();
    }
}
