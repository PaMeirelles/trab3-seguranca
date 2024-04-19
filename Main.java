import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        String data = "Hello, World!";
        byte[] dataBytes = data.getBytes("UTF-8");

        MySignature sig = MySignature.getInstance("SHA512withRSA");
        sig.initSign(privateKey);
        sig.update(dataBytes);
        sig.sign();

        String signatureBase64 = Base64.getEncoder().encodeToString(sig.data);
        System.out.println("Signature: " + signatureBase64);

        MySignature verifier = MySignature.getInstance("SHA512withRSA");
        verifier.initVerify(publicKey);
        verifier.update(dataBytes);
        boolean verified = verifier.verify(sig.data);

        // Print verification result
        if (verified) {
            System.out.println("Signature verified successfully.");
        } else {
            System.out.println("Signature verification failed.");
        }
    }
}
