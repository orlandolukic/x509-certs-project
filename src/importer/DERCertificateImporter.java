package importer;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.cert.X509Certificate;

public class DERCertificateImporter extends CertificateImporter
{
	/**
	 * Creates DER Certificate importer.
	 * 
	 * @param file - Resource from which import is happening.
	 */
	public DERCertificateImporter(File file) 
	{
		super(file);	
	}

	@Override
	public void importCertificates() 
	{
		byte[] bytes = null;
		try {
	        BufferedInputStream reader = new BufferedInputStream(  new FileInputStream(file) );
	        
        	// Check if .pem file starts with "-----BEGIN CERTIFICATE-----"
	        int size = reader.available();
	        bytes = new byte[size];
	        reader.read(bytes);
	        		    
		    X509Certificate cert = generateCertificateFromDER( bytes );
		    certificates = new X509Certificate[1];
		    certificates[0] = cert;
		    reader.close();
		} catch ( Exception e ) {} 	    
	}

}
