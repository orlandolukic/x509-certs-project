package storage;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.Time;

import GUI.GuiManipulation;
import certificate.CertificateCreator;
import factory.KeyPairGen;
import gui.Constants;
import implementation.MyCode;
import util.StringParser;
import x509.v3.GuiV3;

public class KeyPairStorageElement extends StorageElement
{
	private String serial;
	private String subject;
	private Date notBefore,
				 notAfter;
	private KeyPair keypair;
	private String digest;
	
	private boolean isCA;
	private X509Certificate certificate;
	private boolean[] critical;
	
	public KeyPairStorageElement( String alias, GuiV3 gui ) 
	{
		super( alias );
		
		// Init fields of the keypair storage element.
		this.subject = StringParser.readSubjectInfo(gui);
		this.serial = gui.getSerialNumber();
		this.notBefore = gui.getNotBefore();
		this.notAfter = gui.getNotAfter();
		this.digest = gui.getPublicKeyDigestAlgorithm();
		this.isCA = gui.isCA();
		
		// Init critical vector.
		this.critical = GuiManipulation.getActiveCriticalExtensions(gui);
		
		// Create keypair.
		try {
			this.keypair = KeyPairGen.generateEC( gui.getPublicKeyECCurve() );
		} catch (Exception e) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		};			
		
		Extension[] exts = null;
		try {
			// Load certificate's extensions.
			exts = GuiManipulation.getActiveExtensions(gui);             
		} catch (Exception e) {								
			if ( MyCode.DEBUG )
				e.printStackTrace();			
		};	
		generateSelfSignedCertificate( exts );			
	}
	
	/**
	 * Creates self-signed certificate. 
	 */
	private void generateSelfSignedCertificate(Extension[] ext)
	{
		try {
			this.certificate = CertificateCreator.createSelfSignedCertificate(subject, serial, digest, notBefore, notAfter, keypair, ext);
		} catch (Exception e) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		}
	}

	@Override
	public boolean isKeypair() {
		return true;
	}

	@Override
	public X509Certificate getCertificate() throws Exception 
	{		
		return certificate;
	}

	@Override
	public void destruct() {}

	@Override
	public KeyPair getKeypair() throws Exception 
	{		
		return keypair;
	}
	
	/**
	 * Gets serial number.
	 * 
	 * @return serial number of the keypair.
	 */
	public String getSerialNumber()
	{
		return serial;
	}
	
	/**
	 * Gets start date for certificate validity.
	 * 
	 * @return start date.
	 */
	public Date getNotBefore()
	{
		return notBefore;
	}
	
	/**
	 * Gets end date for cerificate validity.
	 * 
	 * @return end date.
	 */
	public Date getNotAfter()
	{
		return notAfter;
	}
	
	/**
	 * Returns certificate's subject info.
	 * 
	 * @return subject info.
	 */
	public String getSubject()
	{
		return subject;
	}
	
	/**
	 * Gets digest of the keypair.
	 * 
	 * @return digest.
	 */
	public String getPublicKeyDigestAlgorithm()
	{
		return digest;
	}
	
	/**
	 * Checks if issuer of the certificate is CA.
	 * 
	 * @return {@code true} if certificate is CA.
	 */
	public boolean isCA()
	{
		return isCA;
	}

	@Override
	public String getCertPublicKeyAlgorithm() {
		try {
			return certificate == null ? keypair.getPublic().getAlgorithm() : certificate.getPublicKey().getAlgorithm();
		} catch (Exception e) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		};
		return null;
	}
}
