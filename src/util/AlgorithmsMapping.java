package util;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedDataGenerator;

import implementation.MyCode;

public class AlgorithmsMapping {

	private static final Map<String, String>     encryptionAlgs = new HashMap<>();
	private static final Map<String, String>     digestAlgs = new HashMap<>();

	public static void init()
	{	
		/*
	    encryptionAlgs.put(X9ObjectIdentifiers.id_dsa_with_sha1.getId(), "DSA");
	    encryptionAlgs.put(X9ObjectIdentifiers.id_dsa.getId(), "DSA");
	    encryptionAlgs.put(OIWObjectIdentifiers.dsaWithSHA1.getId(), "DSA");
	    encryptionAlgs.put(PKCSObjectIdentifiers.rsaEncryption.getId(), "RSA");
	    encryptionAlgs.put(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "RSA");
	    encryptionAlgs.put(X509ObjectIdentifiers.id_ea_rsa.getId(), "RSA");
	    */
	    
	    encryptionAlgs.put(CMSSignedDataGenerator.ENCRYPTION_ECDSA, "ECDSA");	    
	    encryptionAlgs.put(X9ObjectIdentifiers.ecdsa_with_SHA1.getId(), "SHA1withECDSA");
	    encryptionAlgs.put(X9ObjectIdentifiers.ecdsa_with_SHA2.getId(), "SHA2withECDSA");
	    encryptionAlgs.put(X9ObjectIdentifiers.ecdsa_with_SHA224.getId(), "SHA224withECDSA");
	    encryptionAlgs.put(X9ObjectIdentifiers.ecdsa_with_SHA256.getId(), "SHA256withECDSA");
	    encryptionAlgs.put(X9ObjectIdentifiers.ecdsa_with_SHA384.getId(), "SHA384withECDSA");
	    encryptionAlgs.put(X9ObjectIdentifiers.ecdsa_with_SHA512.getId(), "SHA512withECDSA");	    	    

	    /*
	    digestAlgs.put(PKCSObjectIdentifiers.md5.getId(), "MD5");
	    digestAlgs.put(OIWObjectIdentifiers.idSHA1.getId(), "SHA1");
	    digestAlgs.put(NISTObjectIdentifiers.id_sha224.getId(), "SHA224");
	    digestAlgs.put(NISTObjectIdentifiers.id_sha256.getId(), "SHA256");
	    digestAlgs.put(NISTObjectIdentifiers.id_sha384.getId(), "SHA384");
	    digestAlgs.put(NISTObjectIdentifiers.id_sha512.getId(), "SHA512");
	    digestAlgs.put(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "SHA1");	    
	    digestAlgs.put(PKCSObjectIdentifiers.sha224WithRSAEncryption.getId(), "SHA224");
	    digestAlgs.put(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), "SHA256");
	    digestAlgs.put(PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(), "SHA384");
	    digestAlgs.put(PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(), "SHA512");
	    digestAlgs.put(TeleTrusTObjectIdentifiers.ripemd128.getId(), "RIPEMD128");
	    digestAlgs.put(TeleTrusTObjectIdentifiers.ripemd160.getId(), "RIPEMD160");
	    digestAlgs.put(TeleTrusTObjectIdentifiers.ripemd256.getId(), "RIPEMD256");	    
	    digestAlgs.put(CryptoProObjectIdentifiers.gostR3411.getId(),  "GOST3411");
	    digestAlgs.put("1.3.6.1.4.1.5849.1.2.1",  "GOST3411");
	    */
	}

	/*
	public static String getDigestAlgName(String digestAlgOID) 
	{
	    String algName = (String)digestAlgs.get(digestAlgOID);

	    if (algName != null)
	    {
	        return algName;
	    }

	    return digestAlgOID;
	}

	public static String getEncryptionAlgName(String encryptionAlgOID) 
	{
	    String algName = (String)encryptionAlgs.get(encryptionAlgOID);

	    if (algName != null)
	    {
	        return algName;
	    }

	    return encryptionAlgOID;
	}
	*/
	
	/**
	 * Gets signature algorithm based on ObejctIdentifier.
	 * 
	 * @param oid - object identifier of the algorithm.
	 * @return name of the algorithm.
	 */
	public static String getSignatureAlgorithm( String oid )
	{
		try {
			String f = encryptionAlgs.get(oid);
			return f;
		} catch( Exception e ) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		};
		return null;
	}

}
