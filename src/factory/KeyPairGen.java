package factory;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class KeyPairGen 
{
	
	/**
	 * Generates keypair.
	 * 
	 * @return keypair based on algorithm.
	 */
	public static KeyPair generate( String algorithm )
	{
		try {
			Security.addProvider( new BouncyCastleProvider() );
			KeyPairGenerator gen = KeyPairGenerator.getInstance(algorithm, "BC");
			switch( algorithm )
			{
			// Generate RSA keypair.
			case "RSA":				
				gen.initialize(2048);
				break;	
				
			// Generate DSA keypair.
			case "DSA":			
				gen.initialize(1024);
				break;
			
			// Generate EC keypair.
			case "EC":
				SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
				gen.initialize(256, random);
				break;				
			};
			
			return gen.generateKeyPair();
		} catch( Exception e ) {};
		
		return null;		
	}
	
	/**
	 * Creates EC keypair.
	 * 
	 * @param curve - given curve.
	 * @return keypair.
	 * @throws Exception - in case of an error.
	 */
	public static KeyPair generateEC( String curve ) throws Exception
	{
		Security.addProvider( new BouncyCastleProvider() );
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");		
		ECGenParameterSpec spec = new ECGenParameterSpec(curve);
		g.initialize(spec, new SecureRandom());		
		return g.generateKeyPair();		
	}
}
