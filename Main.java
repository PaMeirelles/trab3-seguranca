// Rafael Paladini Meirelles - 2111538
// Bernardo Luiz Bach - 1613231

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws Exception {
        MySignature sig = MySignature.getInstance("SHA512withRSA");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        // Data to be signed
        String data = "Hello, World!";
        byte[] dataBytes = data.getBytes("UTF-8");

        // Sign the data
        sig.initSign(privateKey);
        sig.update(dataBytes);
        sig.sign();

        // Convert signature to base64 for easier handling
        String signatureBase64 = Base64.getEncoder().encodeToString(sig.data);
        System.out.println("Signature: " + signatureBase64);
    }
}
