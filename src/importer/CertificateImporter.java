package importer;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public abstract class CertificateImporter 
{	
	protected File file;
	protected X509Certificate[] certificates;
	
	/**
	 * Creates importer.
	 * 
	 * @param file - Certificate file. [.pem, .der, .crt, .cer]
	 */
	public CertificateImporter(File file)
	{
		this.file = file;
	}
	
	/**
	 * Abstract method for certificate import.
	 */
	public abstract void importCertificates();
	
	/**
	 * Generates X509Certificate based on binary DER bytes.
	 * 
	 * @param certBytes - Bytes retrieved from DER file.
	 * @return certificate X509Certificate
	 * @throws CertificateException - In case of an error, exception is thrown.
	 */
	protected X509Certificate generateCertificateFromDER(byte[] certBytes) throws CertificateException 
	{
        final CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
    }	
	
	/**
	 * Gets certificates that are imported.
	 * 
	 * @return imported certificates.
	 */
	public X509Certificate[] getCertificates() 
	{
		return certificates;
	}
	
	/**
	 * Gets number of certificates.
	 * 
	 * @return certificate number.
	 */
	public int getCertificateNumber()
	{
		return certificates == null ? 0 : certificates.length;
	}
	
	/**
	 * Checks if imported certificates are in chain.
	 *  
	 * @return {@code true} if multiple certificates are imported.
	 */
	public boolean isChain()
	{
		return certificates == null ? false : certificates.length > 1;
	}
	
	/**
	 * Gets last certificate in chain.
	 * 
	 * @return last certificate from chain.
	 */
	public X509Certificate getLastCertificate()
	{
		return certificates != null ? certificates[ certificates.length - 1 ] : null;
	}
	
	/**
	 * Destruct importer.
	 */
	public void destruct()
	{
		file = null;
		certificates = null;
	}
}
