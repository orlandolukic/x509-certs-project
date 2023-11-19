package storage;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

public abstract class StorageElement 
{
	protected String alias;
	
	public StorageElement( String alias )
	{
		this.alias = alias;
	}
	
	/**
	 * Creates storage element as keypair.
	 * 
	 * @param alias
	 * @throws Exception
	 */
	/*
	public StorageElement( String alias ) throws Exception
	{
		this.isKeypair = true;
		this.canModify = true;
		this.alias = alias;
		this.store = KeyStore.getInstance( KeyStore.getDefaultType() );	
		this.store.load( null );
	}*/
	
	/**
	 * Create storage element by importing certificate.
	 * 
	 * @param file - File of the certificate.
	 * @param alias - Alias of the keypair.
	 */
	/*
	public StorageElement( String file, String alias ) throws Exception
	{
		this.isKeypair = true;
		
		this.alias = alias;
		this.store = null;
		
		File f = new File(file);
		if ( !f.exists() )
			throw new Exception("File " + file + " could not be found!");
		
		String ext = StringParser.getFileExtension(f);
		
		// Check file's extension.
		CertificateImporter importer = null;
		switch( ext )
		{
		// Load .PEM extension.
		case "pem": case "PEM":
			importer = new PEMCertificateImporter(f);
			break;
		}
		importer.importCertificates();
		
	}
	*/
	
	/**
	 * Creates storage element with alias from file .p12
	 * 
	 * @param alias - Name of the element.
	 * @param file - Name of the file (.p12).
	 * @param password - Password of the file.
	 * @param keypair - Whether storage element is keypair (or certificate).
	 */
	/*
	public StorageElement( String alias, String file, String password ) throws Exception
	{
		this.alias = alias;
		this.isKeypair = true;
		this.file = file;
		this.store = KeyStore.getInstance( KeyStore.getDefaultType() );
		this.password = password;

		File f = new File(file);
		if ( !f.exists() )
			throw new Exception("File " + file + " could not be found!");
		
		
		fis = new FileInputStream(f);			 
		store.load( fis, password.toCharArray() );			
		
		/*
		System.out.println( "here " + store.isKeyEntry("etfrootca") );
		
		ProtectionParameter protParam = new KeyStore.PasswordProtection(password.toCharArray());

	    // get my private key
	    PrivateKeyEntry pkEntry = (PrivateKeyEntry) store.getEntry("etfrootca", protParam);
	    PrivateKey myPrivateKey = pkEntry.getPrivateKey();

	    Certificate cert = store.getCertificate("etfrootca");
	    PublicKey p = cert.getPublicKey();
	    
	    System.out.println( "PRIVATE " + ((RSAPrivateKey)(myPrivateKey)).getModulus().toString(16) + " PUBLIC:" + p.getEncoded() );
	    
	    KeyPair pair = new KeyPair(p, myPrivateKey);
	    System.out.println( ((RSAPrivateKey)pair.getPrivate()).getModulus().toString(16) );	
	} */
	
	/**
	 * Gets alias for this storage element.
	 * 
	 * @return alias of this storage element.
	 */
	public String getAlias()
	{
		return alias;
	}
	
	/**
	 * Detects whether storage element is keypair.
	 * 
	 * @return indication of element's state.
	 */
	public abstract boolean isKeypair();
	
	/**
	 * Gets certificate for this storage element.
	 * 
	 * @return
	 */
	public abstract X509Certificate getCertificate() throws Exception;
	
	/**
	 * Method which is called right before the destruction of the storage element.
	 */
	public abstract void destruct();
	
	/**
	 * Gets keypair for this storage element.
	 * 
	 * @return
	 * @throws Exception
	 */
	public abstract KeyPair getKeypair() throws Exception;
	
	/**
	 * Gets certificate's public key algorithm.
	 * 
	 * @return public key's algorithm.
	 */
	public abstract String getCertPublicKeyAlgorithm();
}
