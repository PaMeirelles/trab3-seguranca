// Rafael Paladini Meirelles - 2111538
// Bernardo Luiz Bach - 1613231

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class MySignature {
    private static final HashSet<String> allowedAlgo = new HashSet<>(Arrays.asList(
            "MD5WITHRSA",
            "SHA1WITHRSA",
            "SHA256WITHRSA",
            "SHA512WITHRSA",
            "SHA256WITHECDSA"
    ));
    private static final String VERIFY = "VERIFY";
    private static final String SIGN = "SIGN";

    private static String digestType;
    private static String signType;

    private PrivateKey privateKey;
    private final MessageDigest md;
    public byte[] data;
    private PublicKey publicKey;
    private String mode;

    public static void fillAlgoTypes(String algo) throws NoSuchAlgorithmException {
        Pattern pattern = Pattern.compile("(MD5|SHA)(\\d{0,3})WITH(.*)");
        Matcher matcher = pattern.matcher(algo.toUpperCase());
        if (matcher.matches()) {
            String g1 = matcher.group(1);
            String g2 = matcher.group(2);

            if(Objects.equals(g1, "SHA")){
                g2 = "-" + g2;
            }

            digestType = g1 + g2;
            signType = matcher.group(3);
        } else {
            throw new NoSuchAlgorithmException(algo);
        }
    }

    private MySignature(String algo) throws NoSuchAlgorithmException {
        fillAlgoTypes(algo);
        md = MessageDigest.getInstance(digestType);
    }

    public static MySignature getInstance(String algo) throws NoSuchAlgorithmException {
        if (!allowedAlgo.contains(algo.toUpperCase())) {
            throw new NoSuchAlgorithmException(algo);
        }
        return new MySignature(algo);
    }

    final void initSign(PrivateKey pk){
        mode = SIGN;
        privateKey = pk;
        data = new byte[]{};
        md.reset();
    }

    final void update(byte[] newData){
        md.update(newData);
    }

    final void sign() throws Exception {
        if(Objects.equals(VERIFY, mode)){
            throw new Exception("Não é possível assinar durante o modo de verificação!");
        }
        if(Objects.equals(signType, "RSA")){
            byte[] digest = md.digest();
            BigInteger message = new BigInteger(1, digest);
            BigInteger modulus = ((java.security.interfaces.RSAPrivateKey) privateKey).getModulus();
            BigInteger privateExponent = ((java.security.interfaces.RSAPrivateKey) privateKey).getPrivateExponent();

            BigInteger sig = message.modPow(privateExponent, modulus);

            data = sig.toByteArray();
        }
        else if(Objects.equals(signType, "ECDSA")){
            // TODO
            throw new UnsupportedOperationException("ECDSA signing logic not implemented yet");
        }
        else{
            throw new UnsupportedOperationException("Signing algorithm not supported: " + signType);
        }
    }

    final void initVerify(PublicKey pk){
        mode = VERIFY;
        publicKey = pk;
        data = new byte[]{};
        md.reset();
    }

    final boolean verify(byte[] signature) throws Exception {
        if(Objects.equals(SIGN, mode)){
            throw new Exception("Não é possível assinar durante o modo de verificação!");
        }
        if(Objects.equals(signType, "RSA")) {
            BigInteger signatureBigInt = new BigInteger(1, signature);
            BigInteger modulus = ((java.security.interfaces.RSAPublicKey) publicKey).getModulus();
            BigInteger publicExponent = ((java.security.interfaces.RSAPublicKey) publicKey).getPublicExponent();
            BigInteger decryptedSignature = signatureBigInt.modPow(publicExponent, modulus);

            byte[] hashOfData = md.digest();

            BigInteger dataHashBigInt = new BigInteger(1, hashOfData);

            return decryptedSignature.equals(dataHashBigInt);
        }
        else if(Objects.equals(signType, "ECDSA")){
            // TODO
            throw new UnsupportedOperationException("ECDSA signing logic not implemented yet");
        }
        else{
            throw new UnsupportedOperationException("Signing algorithm not supported: " + signType);
        }
    }
}
