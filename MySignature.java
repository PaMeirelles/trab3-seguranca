import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;

public class MySignature {
    private static final HashSet<String> allowedAlgo = new HashSet<>(Arrays.asList(
            "MD5WITHRSA",
            "SHA1WITHRSA",
            "SHA256WITHRSA",
            "SHA512WITHRSA",
            "SHA256WITHECDSA"
    ));

    private String algorithm;

    private MySignature(String algo) {
        algorithm = algo;
    }

    public static MySignature getInstance(String algo) throws NoSuchAlgorithmException {
        if (!allowedAlgo.contains(algo.toUpperCase())) {
            throw new NoSuchAlgorithmException("Algorithm not supported");
        }
        return new MySignature(algo);
    }
}
