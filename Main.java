import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) {
        try {
            MySignature sig = MySignature.getInstance("MD5WITHRSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
