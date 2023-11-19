package exporter;

import java.io.File;
import java.io.PrintWriter;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import implementation.MyCode;
import storage.StorageElement;

public abstract class CertificateExporter 
{
	protected String alias;
	protected File file;
	protected PrintWriter writer;
	protected Certificate[] certificates;
	
	/**
	 * Public constructor.
	 * 
	 * @param file - Path of the file.
	 * @param element - Storage element for which export is happening.
	 * @throws Exception - Exception is thrown in case of an error.
	 */
	public CertificateExporter( String file, String alias ) throws Exception
	{
		this.alias = alias;
		this.file = new File(file);
		this.writer = new PrintWriter( file );
	}
	
	/**
	 * Initializes certificates for this exporter.
	 */
	public abstract void setCertificates() throws Exception;
	
	/**
	 * Exports certificates and closes output stream.
	 */
	public void exportCertificates() throws Exception
	{		
		try {
			// Sets certificates for exporter.
			setCertificates();
			
			_exportCertificates();
		} catch ( Exception e ) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
			throw e;
		} finally {
			if ( writer != null )
				writer.close();
		};
	}
	
	/**
	 * Do that certificate export thang!
	 * 
	 * @throws Exception in case of an error.
	 */
	protected abstract void _exportCertificates() throws Exception;
}
