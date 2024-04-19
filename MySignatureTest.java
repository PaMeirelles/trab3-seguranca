// Rafael Paladini Meirelles - 2111538
// Bernardo Luiz Bach - 1613231

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class MySignatureTest {
    public static void main(String[] args) throws Exception {
        String algorithm = args[0];
        String message = args[1];

        MySignature sig = MySignature.getInstance(algorithm);

        System.out.println("1. Generating asymmetric key pair...");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(MySignature.signType);
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        System.out.println("   Asymmetric key pair generated successfully.");
        System.out.println("   Private Key: " + privateKey.toString());
        System.out.println("   Public Key: " + publicKey.toString());

        System.out.println("2. Signing message...");
        byte[] dataBytes = message.getBytes(StandardCharsets.UTF_8);
        sig.initSign(privateKey);
        sig.update(dataBytes);
        sig.sign();
        byte[] signature = sig.data;
        String signatureHex = bytesToHex(signature);
        System.out.println("   Message signed successfully.");
        System.out.println("   Signature (Hexadecimal): " + signatureHex);

        System.out.println("3. Verifying signature...");
        sig.initVerify(publicKey);
        sig.update(dataBytes);
        boolean verified = sig.verify(signature);
        System.out.println("   Signature verification " + (verified ? "succeeded." : "failed."));

        String messageDigestHex = bytesToHex(sig.md.digest());
        System.out.println("\nMessage Digest (Hexadecimal): " + messageDigestHex);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
