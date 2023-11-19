package exporter;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;

import keystore.LocalKeyStore;
import storage.StorageElement;

public class DERCertificateExporter extends CertificateExporter 
{
	/**
	 * Creates DER certificate exporter.
	 * 
	 * @param file - Name of the file to which is certificate exporting.
	 * @param alias - Name of the certificate.
	 * @throws Exception is throws in case of an error.
	 */
	public DERCertificateExporter(String file, String alias) throws Exception 
	{
		super(file, alias);		
	}

	@Override
	public void setCertificates() throws Exception 
	{
		certificates = new X509Certificate[1];
		certificates[0] = LocalKeyStore.getInstance().getCertificate(alias);		
	}

	@Override
	protected void _exportCertificates() throws Exception 
	{
		writer.close();
		
		byte[] tempBytes = certificates[0].getEncoded(); 
		ASN1InputStream in = new ASN1InputStream(tempBytes); 
		ByteArrayOutputStream bOut = new ByteArrayOutputStream(); 
		DEROutputStream dOut = new DEROutputStream(bOut); 
		dOut.writeObject(in.readObject()); 
		byte[] derData = bOut.toByteArray(); 
		
		FileOutputStream fos = new FileOutputStream(file);
		fos.write(derData);
		fos.flush();		
		
		dOut.close();
		bOut.close();
		in.close();
		fos.close();
	}

}
