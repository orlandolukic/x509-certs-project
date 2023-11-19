package storage;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import implementation.MyCode;

public class P12StorageElement extends StorageElement
{
	private String password;
	private String file;
	private KeyStore store;
	private FileInputStream fis;
	
	/**
	 * Creates storage element with alias from file .p12
	 * 
	 * @param alias - Name of the element.
	 * @param file - Name of the file (.p12).
	 * @param password - Password of the file.
	 * @param keypair - Whether storage element is keypair (or certificate).
	 */
	public P12StorageElement( String alias, String file, String password ) throws Exception
	{
		super( alias );
		this.alias = alias;
		this.file = file;
		this.store = KeyStore.getInstance( "PKCS12" );
		this.password = password;		
		
		fis = new FileInputStream( new File(file) );			 
		store.load( fis, password.toCharArray() );	
		
		// Try to get certificate and private key for given alias.
		store.getCertificate( alias );
		store.getKey(alias, password.toCharArray());
		
		try {
			fis.close();
		} catch( Exception e ) {}
	}
	
	/**
	 * Gets alias of local storage.
	 * 
	 * @return alias.
	 */
	public String getAlias()
	{
		return alias;
	}
	
	/**
	 * Gets keystore for particular storage element.
	 * 
	 * @return keystore.
	 */
	public KeyStore getData()
	{
		return store;
	}
	
	/**
	 * Gets file name for the storage element.
	 * 
	 * @return file name.
	 */
	public String getFile()
	{
		return file;
	}
	
	/**
	 * Gets private key for this P12 storage.
	 * 
	 * @return
	 * @throws Exception
	 */
	public PrivateKey getPrivateKey() throws Exception
	{		
		return (PrivateKey) store.getKey( alias, password.toCharArray() );
	}
	
	/**
	 * Method which is called right before the destruction of the storage element.
	 */
	@Override
	public void destruct()
	{		
		store = null;		
		try {
			if ( fis != null )
				fis.close();
		} catch (IOException e) {}
	}

	@Override
	public boolean isKeypair() 
	{
		return false;
	}

	/**
	 * Gets certificate for this storage element.
	 * 
	 * @return
	 */
	@Override
	public X509Certificate getCertificate() throws Exception
	{
		Certificate[] arr = getCertificates();			
		return arr != null ? (X509Certificate)arr[0] : null;
	}
	
	/**
	 * Gets certificate chain from P12 store based on alias.
	 * 
	 * @return certificate chain.
	 */
	public Certificate[] getCertificates()
	{
		try {
			return (Certificate[]) store.getCertificateChain(alias);
		} catch (KeyStoreException e) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Checks if storage element is imported from outside.
	 * 
	 * @return indicator whether file is imported from outside the system.
	 */
	public boolean isImported()
	{
		return fis != null;
	}
	
	/**
	 * Gets keypair for this element.
	 * 
	 * @return keypair.
	 */
	@Override
	public KeyPair getKeypair() throws Exception
	{		
		
		X509Certificate cert = (X509Certificate) store.getCertificate(alias);
		if ( cert == null )
			throw new Exception( "Could not find certificate with alias " + alias + "." );
		PublicKey pubk = store.getCertificate( alias ).getPublicKey();
		PrivateKey prk = (PrivateKey) store.getKey(alias, password.toCharArray());
		return new KeyPair( pubk, prk );		
	}

	@Override
	public String getCertPublicKeyAlgorithm() {
		try {
			return getCertificate().getPublicKey().getAlgorithm();
		} catch (Exception e) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		}
		return null;
	}
}
