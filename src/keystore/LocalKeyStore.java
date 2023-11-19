package keystore;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.NoSuchElementException;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.operator.*;

import GUI.GuiManipulation;
import exporter.CertificateExporter;
import exporter.DERCertificateExporter;
import exporter.KeyPairExporter;
import exporter.P7BExporter;
import exporter.PEMCertificateExporter;
import factory.CSRFactory;
import gui.Constants;
import implementation.MyCode;
import storage.CertificateStorageElement;
import storage.KeyPairStorageElement;
import storage.P12StorageElement;
import storage.StorageElement;
import util.AlgorithmsMapping;
import util.StringParser;
import x509.v3.GuiV3;

public class LocalKeyStore
{	
	/**
	 * Instance of this class.
	 */
	private static LocalKeyStore instance;
	public static final String KEYSTORE_FILE = "localkeystore.p12";
	public static final String KEYSTORE_PASSWORD = "passwordForP12";
	
	/**
	 * Gets instance of this class.
	 * 
	 * @return instance of local keystore.
	 */
	public static LocalKeyStore getInstance()
	{
		return instance;
	}
	
	/**
	 * Loads gui.
	 * 
	 * @param gui - GUI to be loaded.
	 */
	public static void loadGui( GuiV3 gui )
	{
		if ( instance != null && instance.gui == null )
			instance.gui = gui;
	}
	
	/**
	 * Initializes local keystore.
	 * 
	 * @throws Exception
	 */
	public static void initialize() throws Exception
	{
		if ( instance == null )
			instance = new LocalKeyStore();		
		
		FileInputStream fis = null;
		instance.keystore = KeyStore.getInstance( "PKCS12" );		
		instance.keystore.load(null, null);
		try {
			fis = new FileInputStream( KEYSTORE_FILE );				
			instance.keystore.load( fis, KEYSTORE_PASSWORD.toCharArray() );
		} catch( FileNotFoundException e ) {}; 
		if ( fis != null )
			fis.close();
	}
	
	
	/**
	 * Storage with StorageElements.
	 */
	private LinkedList<StorageElement> storage;
	private KeyStore keystore;
	private GuiV3 gui;
	private JcaPKCS10CertificationRequest csr;
	
	/**
	 * Constructor for local key store.
	 * 
	 * @param gui - GUI.
	 * @throws KeyStoreException
	 */
	private LocalKeyStore() throws KeyStoreException
	{
		this.storage = new LinkedList<>();
	}
	
	/**
	 * Gets all aliases from the local keystore.
	 * 
	 * @return all aliases in this keystore.
	 * @throws KeyStoreException - In case of an error this Exception is thrown.
	 */
	public Enumeration<String> aliases() throws KeyStoreException
	{
		return keystore.aliases();
	}
	
	/**
	 * Deletes keypair with given alias from local keystore.
	 * 
	 * @param alias - Name of the keypair.
	 */
	public boolean delete( String alias )
	{
		try {			
			keystore.deleteEntry(alias);
			try {
				keystore.aliases().nextElement();
				_saveP12File();
			} catch( NoSuchElementException ex ) {
				File f = new File( KEYSTORE_FILE );
				f.delete();
				keystore = null;
			};		
			return true;
		} catch (KeyStoreException e) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		}
		return false;
	}
	
	/**
	 * Deletes all content from local keystore.
	 */
	public void deleteAll()
	{
		File f = new File( KEYSTORE_FILE );
		f.delete();
		keystore = null;
		try {
			initialize();
		} catch (Exception e) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		}	
	}
	
	/**
	 * Loads keypair from the file.
	 * 
	 * @param alias - Name of the keypair.
	 * @param file - File (.p12) which is imported
	 * @param password - Password for the file.
	 */
	public boolean loadP12keypair( String alias, String file, String password )
	{		
		try {				
			StorageElement element = new P12StorageElement( alias, file, password );
			keystore.setKeyEntry( alias, element.getKeypair().getPrivate(), KEYSTORE_PASSWORD.toCharArray(), new X509Certificate[] { element.getCertificate() } );			
			System.out.println(alias + " " + KEYSTORE_PASSWORD);
		} catch( Exception e ) {			
			GuiV3.reportError(e);
			return false;
		}
		_saveP12File();
		return true;
	}
	
	/**
	 * Checks if alias exists in the system.
	 * 
	 * @param alias - Alias of the entry in the storage.
	 * @return
	 */
	public boolean aliasExist( String alias )
	{
		try {
			return keystore.containsAlias(alias);
		} catch (KeyStoreException e) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		}
		return false;
	}
	
	/**
	 * Gets certificate for given alias.
	 * 
	 * @param alias - Name of the certificate's alias.
	 * @return Certificate.
	 * @throws Exception is thrown in case of an error.
	 */
	public X509Certificate getCertificate( String alias ) throws Exception
	{
		X509Certificate f = (X509Certificate) keystore.getCertificate(alias);
		return f;
	}
	
	/**
	 * Gets certificate chain for given alias.
	 * 
	 * @param alias - Name of the certificate's alias.
	 * @return Certificate chain.
	 * @throws Exception is thrown in case of an error.
	 */
	public Certificate[] getCertificateChain( String alias ) throws Exception
	{
		return (Certificate[]) keystore.getCertificateChain(alias);
	}
	
	/**
	 * Saves keypair from GUI.
	 * 
	 * @param alias - Name of the new keypair.
	 * @param gui - GUI.
	 * @return success indicator.
	 */
	public boolean save( String alias, GuiV3 gui )
	{
		// Check if alias already exists!
		if ( aliasExist( alias ) )
		{
			GuiV3.reportError("Alias with name \"" + alias + "\" already exists in the system.");
			return false;
		}
		
		// Check version of new keypair!
		if ( gui.getVersion() == Constants.V1 )
		{			
			GuiV3.reportError("Only supported version of certificate is V3 (Version 3).");
			return false;
		};		
		
		// Check if algorithm is supported!
		if ( !gui.getPublicKeyAlgorithm().equals("EC") )
		{
			GuiV3.reportError("Only EC public key algorithm is supported!");
			return false;
		};
		
		try {
			KeyPairStorageElement el = new KeyPairStorageElement( alias, gui );
			keystore.setKeyEntry(alias, el.getKeypair().getPrivate(), KEYSTORE_PASSWORD.toCharArray(), new X509Certificate[] { el.getCertificate() });
			_saveP12File();
			return true;
		} catch (Exception e1) {
			if ( MyCode.DEBUG )
				e1.printStackTrace();
		};		
			
		return false;
	}
	
	/**
	 * Method for saving Local Key Store.
	 */
	private void _saveP12File()
	{
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream( KEYSTORE_FILE );
			keystore.store( fos, KEYSTORE_PASSWORD.toCharArray() );			
		} catch( Exception e ) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		} finally {
			if ( fos != null )
				try {
					fos.close();
				} catch (IOException e1) {}
		};
	}
	
	/**
	 * Imports certificate from a file.
	 * 
	 * @param file - File to be imported.
	 * @param keypair_name - Keypair alias.
	 * @return success indicator.
	 */
	public boolean importCertificate( String file, String keypair_name )
	{
		// Check if alias exists!
		if ( aliasExist(keypair_name) )
		{
			GuiV3.reportError("Certificate already exists in the system.");
			return false;
		}
	
		try {			
			StorageElement element = new CertificateStorageElement( file, keypair_name );
			keystore.setCertificateEntry( keypair_name, element.getCertificate() );
			_saveP12File();
			return true;
		} catch (Exception e) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		}
			
		return false;
	}
	
	/**
	 * Exports certificate in wanted format.
	 * 
	 * @param file
	 * @param keypair_name
	 * @param encoding
	 * @param format
	 * @return
	 */
	public boolean exportCertificate( String file, String keypair_name, int encoding, int format )
	{		
		try {
			CertificateExporter exporter = null;			
			switch( encoding )
			{
			// PEM export format.
			case Constants.PEM:
				exporter = new PEMCertificateExporter( file, keypair_name, format == Constants.CHAIN );  
				break;
				
			// DER export format.
			case Constants.DER:		
				exporter = new DERCertificateExporter( file, keypair_name );
				break;
			};
			
			// Do that certificate thang!
			exporter.exportCertificates();
			
			return true;			
		} catch ( Exception e ) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		}
		return false;
	}
	
	/**
	 * Checks if certificate is CA.
	 * 
	 * @param keypair_name - Alias of the certificate.
	 * @return
	 */
	public boolean isCA( String keypair_name )
	{		
		try {
			X509Certificate cert = (X509Certificate) keystore.getCertificate(keypair_name);
			cert.verify( cert.getPublicKey() );
			int ca = cert.getBasicConstraints();
			if ( ca != -1 )
				return true;
		} catch (Exception e) {}
		
		return false;
	}
	
	/**
	 * Gets keypair for alias and exports it!
	 * 
	 * @param alias - Alias of the keypair.
	 * @param file - File path.
	 * @param password - Password for private key protection.
	 * @return
	 */
	public boolean exportKeypair( String alias, String file, String password )
	{				
		try {			
			KeyPairExporter exp = new KeyPairExporter( alias, file, password );
			exp.exportKeypair();
			return true;
		} catch (Exception e) {			
			GuiV3.reportError(e);
			if ( MyCode.DEBUG )
				e.printStackTrace();
		};		
		return false;		
	}
	
	/**
	 * Gets info about the subject.
	 * 
	 * @param file - .CSR file.
	 * @param gui - GUI.
	 * @return subject's data.
	 */
	public String importCSR( String file, GuiV3 gui )
	{
		Security.addProvider( new BouncyCastleProvider() );        
        try {
        	File f = new File(file);
        	FileInputStream fis = new FileInputStream( f );
           
            byte[] data = new byte[(int) f.length()];
            fis.read(data);
            this.csr = new JcaPKCS10CertificationRequest(data);      
            
           fis.close();
        } catch (IOException e) {
        	if ( MyCode.DEBUG )
        		e.printStackTrace();          
        };        
        return csr.getSubject().toString()+",SA=" + csr.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId();
	}
	
	/**
	 * Creates and exports .CSR file.
	 * 
	 * @param file - File for export.
	 * @param alias - Name of the keypair.
	 * @param algorithm - Algorithm used for signing.
	 * @return
	 */
	public boolean exportCSR( String file, String alias, String algorithm )
	{
		CSRFactory fact = new CSRFactory( file, alias, algorithm );
		try {
			fact.createCSR();
			fact.createFile();
			return true;
		} catch (Exception e) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		};			
		return false;
	}
	
	/*
	private String getX500Field(String asn1ObjectIdentifier, X500Name x500Name) 
	{
        RDN[] rdnArray = x500Name.getRDNs(new ASN1ObjectIdentifier(asn1ObjectIdentifier));
        String retVal = null;
        for (RDN item : rdnArray)
            retVal = item.getFirst().getValue().toString();
        return retVal;
    }*/
	
	/**
	 * Gets key for given alias in current keystore.
	 * 
	 * @param alias - Alias of the keypair.
	 * @param password - Password of the key.
	 * @return private key.
	 * @throws Exception is thrown in case key cannot be retrieved.
	 */
	public Key getKey( String alias,  String password ) throws Exception
	{
		return keystore.getKey( alias, password.toCharArray() );
	}
	
	/**
	 * Gets certificate public key's algorithm.
	 * 
	 * @param alias - Name of the keypair.
	 * @return public key's algorithm.
	 */
	public String getCertPublicKeyAlgorithm( String alias ) throws Exception
	{		
		X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);		
		return cert.getPublicKey().getAlgorithm();
	}

	/**
	 * Signs previously generated .CSR file.
	 * 
	 * @param file
	 * @param keypair_name
	 * @param algorithm
	 * @return
	 */
	public boolean signCSR(String file, String keypair_name, String algorithm)
	{		
		try {
			P7BExporter exporter = new P7BExporter( file, keypair_name, algorithm, csr, gui );
			exporter.exportCertificates();
			return true;
		} catch (Exception e) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		}		
		return false;
	}
}
