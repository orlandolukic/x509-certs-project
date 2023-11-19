package certificate;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateCreator 
{
	
	/**
	 * Creates self-signed certificate without extensions.
	 * 
	 * @param subject - Certificate's subject.
	 * @param serial - Serial number of the certificate.
	 * @param digest - Digest algorithm for creation.
	 * @param start - Not before date.
	 * @param end - Not after date.
	 * @param keypair - KeyPair for certificate creation.
	 * @return created certificate.
	 * @throws Exception
	 */
	public static X509Certificate createSelfSignedCertificate(
			String subject,
			String serial,
			String digest,
			Date start,
			Date end,
			KeyPair keypair
	) throws Exception
	{
		return createSelfSignedCertificate( subject, serial, digest, start, end, keypair, null );
	}
	
	/**
	 * Creates self-signed certificate with extensions (V3).
	 * 
	 * 
	 * @param subject - Certificate's subject.
	 * @param serial - Serial number of the certificate.
	 * @param digest - Digest algorithm for creation.
	 * @param start - Not before date.
	 * @param end - Not after date.
	 * @param keypair - KeyPair for certificate creation.
	 * @param extensions - Certificate's extensions.
	 * @return created certificate.
	 * @throws Exception
	 */
	public static X509Certificate createSelfSignedCertificate(
			String subject,			
			String serial,
			String digest,
			Date start,
			Date end,
			KeyPair keypair,
			Extension[] extensions
	) throws Exception
	{
		return createCertificate( subject, subject, serial, digest, start, end, keypair, extensions );
	}
	
	/**
	 * Creates certificate based on subject and issuer.
	 * 
	 * @param subject - Certificate's subject.
	 * @param issuer - Certificate's issuer.
	 * @param serial - Serial number of the certificate.
	 * @param digest - Digest algorithm for creation.
	 * @param start - Not before date.
	 * @param end - Not after date.
	 * @param keypair - KeyPair for certificate creation.
	 * @param extensions - Certificate's extensions.
	 * @return created certificate.
	 * @throws Exception
	 */
	public static X509Certificate createCertificate(
			String subject,
			String issuer,
			String serial,
			String digest,
			Date start,
			Date end,
			KeyPair keypair,
			Extension[] extensions
	) throws Exception
	{
		// Certificate info.
		X500Name dnNameSubject = new X500Name( subject );		     
		X500Name dnNameIssuer = new X500Name( issuer );

        ContentSigner contentSigner = new JcaContentSignerBuilder( digest ).build( keypair.getPrivate() );
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder( dnNameIssuer, new BigInteger( serial ), start, end, dnNameSubject, keypair.getPublic() );        
        
        // Add extensions.
        if ( extensions != null )
        	_addExtensions( certBuilder, extensions );

        return new JcaX509CertificateConverter().getCertificate( certBuilder.build(contentSigner) );
	}
	
	/**
	 * Creates certificate based on subject and issuer.
	 * 
	 * @param subject - Certificate's subject.
	 * @param issuer - Certificate's issuer.
	 * @param serial - Serial number of the certificate.
	 * @param digest - Digest algorithm for creation.
	 * @param start - Not before date.
	 * @param end - Not after date.
	 * @param keypair - KeyPair for certificate creation.
	 * @param extensions - Certificate's extensions.
	 * @return created certificate.
	 * @throws Exception
	 */
	public static X509Certificate createCertificate(
			X500Name subject,
			X500Name issuer,
			String serial,
			String digest,
			Date start,
			Date end,
			KeyPair keypair,
			Extension[] extensions
	) throws Exception
	{
        ContentSigner contentSigner = new JcaContentSignerBuilder( digest ).build( keypair.getPrivate() );
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder( issuer, new BigInteger( serial ), start, end, subject, keypair.getPublic() );        
        
        // Add extensions.
        if ( extensions != null )
        	_addExtensions( certBuilder, extensions );

        return new JcaX509CertificateConverter().getCertificate( certBuilder.build(contentSigner) );
	}
	
	/**
	 * Adds extensions to certificate.
	 * 
	 * @param builder - Builder of the certificate.
	 * @param extensions - Extensions to add.
	 * @access private
	 */
	private static void _addExtensions( JcaX509v3CertificateBuilder builder, Extension[] extensions ) throws Exception
	{
		for ( int i=0,n=extensions.length; i<n; i++ )
			if ( extensions[i] != null )
				builder.addExtension( extensions[i] );
	}
}
