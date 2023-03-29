package org.example;

import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Base64;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

class ECIESEncryption {
    public static void main(String[] args) throws Exception {
        // Add the Bouncy Castle security provider
        Security.addProvider(new BouncyCastleProvider());

        // Generate a new EC key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256); // or any other key size
        KeyPair keyPair = keyGen.generateKeyPair();

        // Get the public key as a byte array
        byte[] publicKey = keyPair.getPublic().getEncoded();

        // Create a Cipher object for encryption
        Cipher cipher = Cipher.getInstance("ECIESwithAES-GCM");

        // Initialize the Cipher object with the public key
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        // Encrypt the plaintext
        String plaintext = "Hello, world!";
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

        // Print the encrypted data as a Base64-encoded string
        System.out.println("Encrypted data: " + Base64.getEncoder().encodeToString(ciphertext));
    }
}

class PrivateKeyReader {

    public static PrivateKey get(String filename)
            throws Exception {

        byte[] bytes = Files.readAllBytes(Paths.get(filename));

        // PEM
        String pem = new String(bytes);

        // Decode base64 encoded content
        byte[] decoded = Base64.getDecoder().decode(pem);
        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePrivate(spec);
    }
}

class PublicKeyReader {

    public static PublicKey get(String filename)
            throws Exception {

        byte[] bytes = Files.readAllBytes(Paths.get(filename));

        // PEM
        String pem = new String(bytes);

        // Decode base64 encoded content
        byte[] decoded = Base64.getDecoder().decode(pem);

        // Create X509EncodedKeySpec from decoded bytes
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(spec);
    }
}

public class Main {
    public static void main(String[] args) throws Exception {
        System.out.println(PrivateKeyReader.get("/tmp/private.key"));
    }
}