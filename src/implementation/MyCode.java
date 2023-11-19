package implementation;

import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;

import GUI.GuiManipulation;
import code.GuiException;
import keystore.LocalKeyStore;
import util.AlgorithmsMapping;
import util.StringParser;
import x509.v3.GuiV3;

public class MyCode extends x509.v3.CodeV3 
{
	private String close;
	
	/**
	 * Whether to debug in console.
	 */
	public static final boolean DEBUG = true;
	
	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
		init();
	}
	
	/**
	 * Inits application.
	 */
	private void init() throws GuiException
	{
		if ( close != null )
			throw new GuiException(close);
		
		AlgorithmsMapping.init();
		LocalKeyStore.loadGui(access);
	}

	@Override
	public boolean canSign(String keypair_name) 
	{		
		return LocalKeyStore.getInstance().isCA(keypair_name);				
	}

	@Override
	public boolean exportCSR(String file, String keypair_name, String algorithm) 
	{
		return LocalKeyStore.getInstance().exportCSR(file, keypair_name, algorithm);		
	}

	@Override
	public boolean exportCertificate(String file, String keypair_name, int encoding, int format) 
	{		
		return LocalKeyStore.getInstance().exportCertificate( file, keypair_name, encoding, format );
	}

	/**
	 * Generates .p12 password-protected file.
	 */
	@Override
	public boolean exportKeypair(String name, String file, String password) 
	{
		return LocalKeyStore.getInstance().exportKeypair(name, file, password);
	}

	@Override
	public String getCertPublicKeyAlgorithm(String keypair_name) 
	{
		String f = null;
		try {			
			return LocalKeyStore.getInstance().getCertPublicKeyAlgorithm( keypair_name );		
		} catch (Exception e) {
			if ( DEBUG )
				e.printStackTrace();
		}
		return f;
	}

	@Override
	public String getCertPublicKeyParameter(String keypair_name) 
	{
		String f = null;
		try {
			X509Certificate cert = LocalKeyStore.getInstance().getCertificate( keypair_name );
			f = LocalKeyStore.getInstance().getCertificate( keypair_name ).getPublicKey().getAlgorithm();	
			switch( f )
			{
			case "RSA":						
				return String.format("%d", ((RSAPublicKey)cert.getPublicKey()).getModulus().bitLength() );
				
			case "DSA":				
				return String.format("%d", ((DSAPublicKey)cert.getPublicKey()).getParams().getP().bitLength() );
			
			case "EC":				
				return ((ECPublicKey)cert.getPublicKey()).getParams().getCurve().getField().toString();				
			}
		} catch (Exception e) {
			if ( DEBUG )
				e.printStackTrace();
		}
		return f;
	}

	@Override
	public String getSubjectInfo(String alias) 
	{
		return StringParser.getSubjectInfo(alias);
	}

	@Override
	public boolean importCAReply(String arg0, String arg1) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String importCSR(String file) 
	{		
		return LocalKeyStore.getInstance().importCSR(file, access);
	}

	@Override
	public boolean importCertificate(String file, String keypair_name) 
	{		
		return LocalKeyStore.getInstance().importCertificate( file, keypair_name );
	}

	@Override
	public boolean importKeypair(String name, String file, String password) 
	{
		LocalKeyStore store = LocalKeyStore.getInstance();
		if ( store.aliasExist(name) )
		{
			GuiV3.reportError("Keypair already exists in the system.");
			return false;
		};
		return LocalKeyStore.getInstance().loadP12keypair(name, file, password);		
	}

	@Override
	public int loadKeypair(String keypair_name) 
	{
		return GuiManipulation.loadKeypair(keypair_name, access);		
	}

	/**
	 * Initialy loads keystore.
	 */
	@Override
	public Enumeration<String> loadLocalKeystore()
	{
		try {
			LocalKeyStore.initialize();
		} catch( Exception e ) {
			close = "Could not initialize local key store. REASON: " + e.getMessage();
			return null;
		};	
		
		try {			
			return LocalKeyStore.getInstance().aliases();			
		} catch (KeyStoreException e) {
			if ( DEBUG )
				e.printStackTrace();
		};
		return null;
	}

	@Override
	public boolean removeKeypair(String keypair_name) 
	{		
		return LocalKeyStore.getInstance().delete(keypair_name);		
	}

	/**
	 * Resets local keystore.
	 */
	@Override
	public void resetLocalKeystore() 
	{	
		LocalKeyStore.getInstance().deleteAll();				
	}

	/**
	 * Saves new keypair in Local KeyStore. 
	 */
	@Override
	public boolean saveKeypair(String keypair_name) 
	{
		try {
			return LocalKeyStore.getInstance().save( keypair_name, access );
		} catch (Exception e) {			
			return false;
		}		
	}

	@Override
	public boolean signCSR(String file, String keypair_name, String algorithm) 
	{
		return LocalKeyStore.getInstance().signCSR( file, keypair_name, algorithm );
	}

}
