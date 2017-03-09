import java.security.Security;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.*;
import java.security.MessageDigest;

public class Dictsetlab {

    public static void main(String[] args) {
      Security.addProvider(new BouncyCastleProvider());

      String plainString = "Plaintext Secret";

      try
            {
      MessageDigest messageDigest = MessageDigest.getInstance("SHA-1", "BC");
      byte[] hashedString = messageDigest.digest(plainString.getBytes());
       System.out.println(hashedString.toString());
     }
     catch(NoSuchAlgorithmException e){
       System.err.println("No such algorithm");
            e.printStackTrace();
     }
     catch(NoSuchProviderException e){
       System.err.println("No such provider");
            e.printStackTrace();
     }
    }


}
