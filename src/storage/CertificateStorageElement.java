package storage;

import java.io.File;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import implementation.MyCode;
import importer.CRTCertificateImporter;
import importer.CertificateImporter;
import importer.DERCertificateImporter;
import importer.PEMCertificateImporter;
import util.StringParser;

public class CertificateStorageElement extends StorageElement
{
	private CertificateImporter importer;
	private File file;
	
	/**
	 * Create storage element by importing certificate.
	 * 
	 * @param file - File of the certificate.
	 * @param alias - Alias of the keypair.
	 */
	public CertificateStorageElement( String file, String alias ) throws Exception
	{		
		super(alias);	
		
		File f = new File(file);
		if ( !f.exists() )
			throw new Exception("File " + file + " could not be found!");
		this.file  = f;
		
		// Get file extension.
		String ext = StringParser.getFileExtension(f);
		
		// Check file's extension.
		switch( ext )
		{
		// Load .PEM extension.
		case "pem": case "PEM":
			importer = new PEMCertificateImporter(f);
			break;
			
		// Load .DER extension.
		case "der": case "DER":
		case "crt": case "CRT":
		case "cer": case "CER":
			importer = new DERCertificateImporter(f);
			break;
		};
		
		// Do that import certificates thang!
		importer.importCertificates();		
	}

	@Override
	public boolean isKeypair() {
		return false;
	}

	@Override
	public X509Certificate getCertificate() throws Exception {
		return importer.getLastCertificate();
	}
	
	/**
	 * Gets all certificates.
	 * 
	 * @return array of all certificates.
	 */
	public X509Certificate[] getAllCertificates() 
	{
		return importer.getCertificates();
	}

	@Override
	public void destruct() {	
		importer.destruct();
	}

	@Override
	public KeyPair getKeypair() throws Exception {		
		return null;
	}

	@Override
	public String getCertPublicKeyAlgorithm() {
		try {
			return this.getCertificate().getPublicKey().getAlgorithm();
		} catch (Exception e) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		}
		return null;
	}
	
	
	
	

}
