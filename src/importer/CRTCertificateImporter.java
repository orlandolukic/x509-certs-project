package importer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.xml.bind.DatatypeConverter;

import implementation.MyCode;

public class CRTCertificateImporter extends CertificateImporter
{

	public CRTCertificateImporter(File file) 
	{
		super(file);		
	}

	@Override
	public void importCertificates() 
	{
		byte[] bytes;
		X509Certificate cert = null;		
		boolean started = false;
        
        // Start examining .crt file.
		try {
			BufferedReader reader = new BufferedReader(new FileReader(file));
	        StringBuilder b = new StringBuilder();
	        String str = reader.readLine();
	        while (str != null) 
	        {
	            if ( started && str.contains("END CERTIFICATE") ) 
	            {
	                String hexString = b.toString();
	                bytes = DatatypeConverter.parseBase64Binary(hexString);
	                cert = generateCertificateFromDER(bytes);                
	            } else {
	            	// Skip line => "-----BEGIN CERTIFICATE-----"
	                if ( !str.startsWith("-----") && started )
	                    b.append(str);	 
	                else if ( str.startsWith("-----") )
	                	started = true;
	            };
	            str = reader.readLine();
		    }
		    reader.close();
		    certificates = new X509Certificate[1];
		    certificates[0] = cert;
		} catch( Exception e ) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		}
		
	}

}
