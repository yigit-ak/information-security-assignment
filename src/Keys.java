import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Keys {
    // key pair created using RSA
    static PublicKey publicKeyA;
    static PrivateKey privateKeyA;

    // key pairs created using ecliptic curve
    static PublicKey publicKeyB;
    static PrivateKey privateKeyB;
    static PublicKey publicKeyC;
    static PrivateKey privateKeyC;

    // symmetric keys to be created using derivation function
    static Key symmetricKey1;
    static Key symmetricKey2;

    // symmetric key to be created using ecliptic key
    static Key symmetricKey3;
}