package exporter;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import certificate.CertificateCreator;
import keystore.LocalKeyStore;
import storage.KeyPairStorageElement;

public class KeyPairExporter 
{
	private String alias;	
	private String name;
	private String password;
	
	/**
	 *  Creates exporter for keypair.
	 * 
	 * @param alias - Alias of the keypair.
	 * @param name - Name of the fil
	 * @param password
	 * @throws Exception
	 */
	public KeyPairExporter( String alias, String name, String password) throws Exception
	{
		this.alias = alias;
		this.name = name;
		this.password = password;
	}
	
	/**
	 * Exports keypair to a filename (.p12).
	 * 
	 * @throws Exception - throws exception in case of an error.
	 */
	public void exportKeypair() throws Exception
	{
		LocalKeyStore lks = LocalKeyStore.getInstance();
		Certificate[] certArr = lks.getCertificateChain(alias);		
		Key pk = lks.getKey( alias, LocalKeyStore.KEYSTORE_PASSWORD );

        // Creates pkcs12 key store in memory.
        KeyStore pkcs12 = KeyStore.getInstance("PKCS12");
        pkcs12.load(null, null);

        // Create entry in pkcs12.
        pkcs12.setKeyEntry( alias, pk, password.toCharArray(), certArr );        

        // Store PKCS#12.
        FileOutputStream output = new FileOutputStream( name );
        pkcs12.store( output, password.toCharArray() );     
        try {
        	output.close();
        } catch ( Exception e ) {}
	}
}
