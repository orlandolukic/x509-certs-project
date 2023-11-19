package factory;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyPair;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import implementation.MyCode;
import storage.KeyPairStorageElement;
import storage.StorageElement;
import util.StringParser;
import x509.v3.GuiV3;

public class CSRFactory 
{
	private String alias;
	private String file;
	private PKCS10CertificationRequest request;
	private String algorithm;
	
	private String alg;
	
	public CSRFactory( String file, String alias, String algorithm )
	{
		this.file = file;
		this.alias = alias;
		this.algorithm = algorithm;
		
		String[] parts = algorithm.split("with");
		alg = parts[1];
	}
	
	/**
	 * Creates CSR request.
	 * 
	 * @throws Exception is thrown in case of an error.
	 */
	public void createCSR() throws Exception
	{
		KeyPair pair = generateKeyPair();		
		String info = StringParser.getSubjectInfo( alias );
		PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
		    new X500Principal( info ), 
		    pair.getPublic()
		);
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder( algorithm );
		ContentSigner signer = csBuilder.build( pair.getPrivate() );
		request = builder.build(signer);		
	}
	
	/**
	 * Creates new .CSR file.
	 */
	public void createFile()
	{		
		try {
			FileOutputStream output = new FileOutputStream( file );
			output.write(request.getEncoded());
			output.flush();
			try {
				output.close();
			} catch( Exception e ) {}
		} catch( Exception e ) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		}
		
	}
	
	/**
	 * Gets keypair for signing request.
	 * 
	 * @return 
	 */
	private KeyPair generateKeyPair() throws Exception
	{
		String algorithm = alg;
		if ( alg.equals("ECDSA") )
			algorithm = "EC";
		return KeyPairGen.generate(algorithm);		
	}
}
