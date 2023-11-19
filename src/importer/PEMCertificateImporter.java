package importer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

public class PEMCertificateImporter extends CertificateImporter
{
	/**
	 * Public constructor.
	 * 
	 * @param file - .PEM file.
	 */
	public PEMCertificateImporter(File file) 
	{
		super(file);
	}

	@Override
	public void importCertificates() 
	{			
		byte[] bytes = null;
		try {
	        List<X509Certificate> result = new ArrayList<X509Certificate>();
	        BufferedReader reader = new BufferedReader(new FileReader(file));
	        
        	// Check if .pem file starts with "-----BEGIN CERTIFICATE-----"
	        String str = reader.readLine();	        	        
	        if (str == null || !str.contains("BEGIN CERTIFICATE")) {
	            reader.close();
	            throw new IllegalArgumentException("No CERTIFICATE found");
	        };
	        
	        // Start examining .pem file.
	        StringBuilder b = new StringBuilder();
	        while (str != null) 
	        {
	            if (str.contains("END CERTIFICATE")) 
	            {
	                String hexString = b.toString();
	                bytes = DatatypeConverter.parseBase64Binary(hexString);
	                X509Certificate cert = generateCertificateFromDER(bytes);
	                result.add(cert);
	                b = new StringBuilder();
	            } else {
	            	// Skip first line => "-----BEGIN CERTIFICATE-----"
	                if (!str.startsWith("----"))
	                    b.append(str);	                
	            };
	            str = reader.readLine();
		    }
		    reader.close();
		    certificates = result.toArray(new X509Certificate[result.size()]);
		} catch ( Exception e ) {} 	    
	}

}
