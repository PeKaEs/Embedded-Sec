package labo1;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.*;
import java.security.MessageDigest;

public class DigsetAndSoOn {

	public static void main(String[] args) {
	       

	       String sTest = "Eloelsddo";
	       byte bSHA1 = 0x01, bSHA256 = 0x04, bSHA512 = 0x06; 
	       byte[] bSHA1Hash = hash(sTest.getBytes(),bSHA1);
	       byte[] bSHA256Hash = hash(sTest.getBytes(),bSHA256);
	       byte[] bSHA512Hash = hash(sTest.getBytes(),bSHA512);
	       
	       System.out.println("SHA1: "+ new String(Hex.encode(bSHA1Hash)));
	       System.out.println("SHA256: "+ new String(Hex.encode(bSHA256Hash)));
	       System.out.println("SHA512: "+ new String(Hex.encode(bSHA512Hash)));
	      
	   }
	
	public static byte[] hash( byte[] bInput, byte bFunction){
		
		Security.addProvider(new BouncyCastleProvider());
		byte[] bDigest = {0x00};
		String sOption;
		
		if (bFunction == 0x01){
			sOption="SHA-1";
		}
		else if(bFunction == 0x04){
			sOption="SHA-256";
		}
		else if(bFunction == 0x06){
			sOption="SHA-512";
		}
		else{
			return bDigest;
		}
		try
	      {

	            MessageDigest mdHash = MessageDigest.getInstance(sOption, "BC");
	            mdHash.update(bInput);

	           bDigest = mdHash.digest();

	      }
	      catch (NoSuchAlgorithmException e)
	      {
	            System.err.println("No such algorithm");
	            e.printStackTrace();
	      }
	      catch (NoSuchProviderException e)
	      {
	            System.err.println("No such provider");
	            e.printStackTrace();
	      }
		return bDigest;
	}
}
