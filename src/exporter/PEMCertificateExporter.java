package exporter;

import java.security.cert.X509Certificate;
import java.util.Base64;

import implementation.MyCode;
import keystore.LocalKeyStore;
import storage.CertificateStorageElement;
import storage.StorageElement;

public class PEMCertificateExporter extends CertificateExporter 
{
	private boolean chain;
	
	/**
	 * Creates PEM Certificate Exporter.
	 * 
	 * @param file - Name of the export file.
	 * @param element - Storage element from which export is made.
	 * @param chain - whether chain should be exported.
	 * @throws Exception
	 */
	public PEMCertificateExporter( String file, String alias, boolean chain ) throws Exception 
	{
		super( file, alias );		
		this.chain = chain;		
	}

	@Override
	public void _exportCertificates() throws Exception 
	{		
		X509Certificate cert;
		for (int i=0, n=certificates.length; i<n; i++)
		{
			cert = (X509Certificate) certificates[i];			
			writer.println("-----BEGIN CERTIFICATE-----");			
			writer.println( new String( Base64.getEncoder().encode( cert.getEncoded() ) ) );			
			writer.println("-----END CERTIFICATE-----");
			
			// Send bytes to the stream!
			writer.flush();
		};		
	}

	@Override
	public void setCertificates() throws Exception
	{
		// Export head only
		if ( !chain )
		{			
			certificates = new X509Certificate[1];
			try {
				certificates[0] = LocalKeyStore.getInstance().getCertificate(alias);
			} catch (Exception e) {
				if ( MyCode.DEBUG )
					e.printStackTrace();
			}
		} else	// Export chain.
		{
			certificates = LocalKeyStore.getInstance().getCertificateChain(alias);
			System.out.println(certificates.length);
		};
	}

}
