import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.HashSet;
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

    private String algorithm;
    private PrivateKey privateKey;
    private MessageDigest md;

    public static String extractDigestAlgo(String algo) throws NoSuchAlgorithmException {
        Pattern pattern = Pattern.compile("(.*)WITH.*");
        Matcher matcher = pattern.matcher(algo.toUpperCase());

        if (matcher.matches()) {
            return matcher.group(1);
        } else {
            throw new NoSuchAlgorithmException(algo);
        }
    }

    private MySignature(String algo) throws NoSuchAlgorithmException {
        algorithm = algo;
        md = MessageDigest.getInstance(extractDigestAlgo(algo));
    }

    public static MySignature getInstance(String algo) throws NoSuchAlgorithmException {
        if (!allowedAlgo.contains(algo.toUpperCase())) {
            throw new NoSuchAlgorithmException(algo);
        }
        return new MySignature(algo);
    }

    final void initSign(PrivateKey pk){
        privateKey = pk;
    }

    final void update(byte[] data){
        md.update(data);
    }

}
