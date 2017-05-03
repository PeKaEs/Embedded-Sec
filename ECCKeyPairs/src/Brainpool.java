
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;


public class Brainpool {
	public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException{
	
		Security.addProvider(new BouncyCastleProvider());
		ECCurve curve = new ECCurve.Fp(
				new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16), // q = p
	            new BigInteger("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", 16), // a
	            new BigInteger("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", 16)); // b
	ECParameterSpec ecSpec = new ECParameterSpec(
	            curve,
	            curve.decodePoint(Hex.decode("048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997")), // G
	            new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16)); // n = q
	KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
	g.initialize(ecSpec, new SecureRandom());
	KeyPair pair = g.generateKeyPair();
	PublicKey pkPub=pair.getPublic();
	System.out.println(pkPub.toString());
	}
}
