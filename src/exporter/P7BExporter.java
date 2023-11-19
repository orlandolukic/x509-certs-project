package exporter;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import GUI.GuiManipulation;
import certificate.CertificateCreator;
import keystore.LocalKeyStore;
import util.StringParser;
import x509.v3.GuiV3;

public class P7BExporter extends CertificateExporter 
{
	private JcaPKCS10CertificationRequest csr;
	private GuiV3 gui;
	
	public P7BExporter( String file, String alias, String algorithm, JcaPKCS10CertificationRequest csr, GuiV3 gui ) throws Exception 
	{
		super(file, alias);
		this.csr = csr;
		this.gui = gui;
		if ( csr == null )
			throw new Exception( "Certification Request (CSR) is not loaded." );
	}

	@Override
	public void setCertificates() throws Exception 
	{			
				
	}

	@SuppressWarnings("deprecation")
	@Override
	protected void _exportCertificates() throws Exception 
	{
		JcaPEMWriter wr = new JcaPEMWriter( writer );
		
		// Start init phase.
		X509Certificate issuerCert = LocalKeyStore.getInstance().getCertificate(alias);
		Certificate[] issuerChain = LocalKeyStore.getInstance().getCertificateChain(alias);
		PrivateKey caPrivateKey = (PrivateKey) LocalKeyStore.getInstance().getKey( alias, LocalKeyStore.KEYSTORE_PASSWORD );
		
		String serial = gui.getSerialNumber();
		String digest = gui.getPublicKeyDigestAlgorithm();
		Date notBefore = gui.getNotBefore();
		Date notAfter = gui.getNotAfter();
		X500Name issuerName = new X500Name( StringParser.getIssuerInfo( issuerCert.getIssuerX500Principal() ) );
		KeyPair keypair = new KeyPair( csr.getPublicKey(), caPrivateKey );
		
		// Get all extensions of the certificate.
		Extension[] exts = GuiManipulation.getActiveExtensions(gui);
		
		// Make certificate!
		X509Certificate cert = CertificateCreator.createCertificate( csr.getSubject(), issuerName, serial, digest, notBefore, notAfter, keypair, exts);
		
		// Write certificate to output stream.
		wr.writeObject(cert);
		for ( Certificate certx : issuerChain )
		{
			wr.writeObject( (X509Certificate)certx );
		};
		wr.flush();
	}

}
