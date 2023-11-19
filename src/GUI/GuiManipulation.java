package GUI;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Set;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import gui.Constants;
import implementation.MyCode;
import keystore.LocalKeyStore;
import storage.KeyPairStorageElement;
import storage.StorageElement;
import util.StringParser;
import x509.v3.GuiV3;

import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;


@SuppressWarnings("deprecation")
public class GuiManipulation {
	
	/**
	 * Loads keypair in gui.
	 * 
	 * @param alias - name of the keypair loaded in storage.
	 * @param gui - object for access to the gui.
	 */
	@SuppressWarnings("unchecked")
	public static int loadKeypair( String alias, GuiV3 gui )
	{
		/*
		 * All extensions - implementation.
		 * 
		 * https://www.programcreek.com/java-api-examples/https/www.programcreek.com/java-api-examples/?code=stevanmilic/X509-certificate-manager/X509-certificate-manager-master/src/main/java/implementation/CertificateHelper.java
		 */
		int ret = -1;		
		try {			
			LocalKeyStore lks = LocalKeyStore.getInstance();			
			
			// Get certificate and fill screen with data.			
			X509Certificate cert = lks.getCertificate( alias );
			BigInteger serial = cert.getSerialNumber();				
			
			gui.setSerialNumber( serial.toString() );
			gui.setVersion( cert.getVersion()-1 );			
			gui.setNotBefore( cert.getNotBefore() );
			gui.setNotAfter( cert.getNotAfter() );			
			
			// Set basic constraints.
			int basicConstraints = cert.getBasicConstraints();
			if ( basicConstraints != -1 )
				gui.setCA(true);		
			if ( basicConstraints != Integer.MAX_VALUE && basicConstraints != -1 )
				gui.setPathLen( String.format("%d", basicConstraints ) );
			
			// Set critical extensions.			
			boolean[] critical = new boolean[3];
			Set<String> criticalSet = cert.getCriticalExtensionOIDs();			
			if ( criticalSet != null )
			{
				String cp = Extension.certificatePolicies.toString();
				Iterator<String> it = criticalSet.iterator();
				String f = null;
				
				while( it.hasNext() )
				{
					f = it.next();
					if ( f.equals( Extension.basicConstraints.toString() ) )
					{
						critical[2] = true;
						gui.setCritical(Constants.BC, true);
					} else if ( f.equals( Extension.certificatePolicies.toString() ) )
					{
						critical[0] = true;
						gui.setCritical( Constants.CP , true);
					} else if ( f.equals( Extension.subjectDirectoryAttributes.toString() ) )
					{
						gui.setCritical( Constants.SDA, true);
						critical[1] = true;
					};
				};
			};
			
			// Set certificate policies.
			byte[] policyBytes = cert.getExtensionValue( Extension.certificatePolicies.getId() );
            if (policyBytes != null) 
            {
                CertificatePolicies policies = CertificatePolicies.getInstance(X509ExtensionUtil.fromExtensionValue(policyBytes));
                PolicyInformation[] policyInformations = policies.getPolicyInformation();
                for (PolicyInformation policyInformation : policyInformations) {
                    ASN1Sequence policyQualifiers = (ASN1Sequence) policyInformation.getPolicyQualifiers().getObjectAt(0);                    
                    gui.setAnyPolicy(true);
                    gui.setCpsUri(policyQualifiers.getObjectAt(1).toString());
                    break;
                };
            };
            
            // Get subject directory attributes.
            byte[] dsab = cert.getExtensionValue( X509Extensions.SubjectDirectoryAttributes.toString() );
            if ( dsab != null )
            {            	     
            	DEROctetString derstr = null;
            	SubjectDirectoryAttributes subjectDirectoryAttributes = SubjectDirectoryAttributes.getInstance(X509ExtensionUtil.fromExtensionValue(dsab));
                Vector<Attribute> attributes = subjectDirectoryAttributes.getAttributes();
                for (Attribute attribute : attributes) 
                {
                    if (attribute.getAttrType().equals(BCStyle.DATE_OF_BIRTH)) 
                    {
                        ASN1UTCTime dateOfBirthTime = (ASN1UTCTime) attribute.getAttrValues().getObjectAt(0);
                        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd");
                        gui.setDateOfBirth( simpleDateFormat.format(dateOfBirthTime.getDate() ) );
                        
                    } else if (attribute.getAttrType().equals(BCStyle.PLACE_OF_BIRTH)) 
                    {
                        derstr = (DEROctetString) attribute.getAttrValues().getObjectAt(0);
                        gui.setSubjectDirectoryAttribute( Constants.POB, new String( derstr.getOctets() ) );
                        
                    } else if (attribute.getAttrType().equals(BCStyle.COUNTRY_OF_CITIZENSHIP)) 
                    {
                        derstr = (DEROctetString) attribute.getAttrValues().getObjectAt(0);
                        gui.setSubjectDirectoryAttribute( Constants.COC, new String(derstr.getOctets()) );
                        
                    } else if (attribute.getAttrType().equals(BCStyle.GENDER)) 
                    {
                        derstr = (DEROctetString) attribute.getAttrValues().getObjectAt(0);
                        gui.setGender( new String(derstr.getOctets()) );
                    };        	
            	};
            };
			
			// Set subject fields.
			gui.setSubject( StringParser.getSubjectInfo(alias) );	
			gui.setSubjectSignatureAlgorithm( cert.getPublicKey().getAlgorithm() );
			
			// Set CA fields.		
			gui.setIssuer( StringParser.getIssuerInfo(alias) );		
			gui.setIssuerSignatureAlgorithm( cert.getSigAlgName() );			
			
			// Determine ret value.
			if ( basicConstraints != -1 )
				ret = 2;
			else if ( cert.getSigAlgName() != null && cert.getSigAlgName() != "" )
				ret = 1;
			else 
				ret = 0;
			
			
		} catch( Exception e ) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		}
		return ret;
	}
	
	/**
	 * Gets currently active critical extensions.
	 * 
	 * @param gui - GUI.
	 * @return array of critical extensions (ordered ASC from screen).
	 */
	public static boolean[] getActiveCriticalExtensions( GuiV3 gui )
	{
		boolean[] critical = new boolean[3];
		
		critical[0] = gui.isCritical( Constants.CP );
		critical[1] = gui.isCritical( Constants.SDA );
		critical[2] = gui.isCritical( Constants.BC );
		
		return critical;
	}
	
	/**
	 * Gets active extensions from the screen.
	 * 
	 * @param gui - GUI.
	 * @return extensions from the certificate.
	 * @throws Exception 
	 */
	public static Extension[] getActiveExtensions( GuiV3 gui ) throws Exception
	{
		LinkedList<Extension> lst = new LinkedList<>();
		boolean[] critical = getActiveCriticalExtensions(gui);
		
		// Set basic constraints.
		BasicConstraints bc = !gui.getPathLen().equals("") ? new BasicConstraints( Integer.parseInt( gui.getPathLen() ) ) : new BasicConstraints( false );
		lst.add( new Extension( new ASN1ObjectIdentifier( "2.5.29.19" ), critical[2], bc.getEncoded() ) );
		
		// Set certificate policies.
		if ( gui.getAnyPolicy() ) 
		{
            PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(gui.getCpsUri());
            PolicyInformation policyInformation = new PolicyInformation( PolicyQualifierId.id_qt_cps, new DERSequence(policyQualifierInfo) );
            CertificatePolicies certificatePolicies = new CertificatePolicies(policyInformation);
           lst.add( new Extension( new ASN1ObjectIdentifier(Extension.certificatePolicies.getId()), gui.isCritical( Constants.CP ), certificatePolicies.toASN1Primitive().getEncoded() ) );
        };
        
        // Set subject directory attributes.
        if ( !gui.getDateOfBirth().equals("") || !gui.getGender().equals("") || !gui.getSubjectDirectoryAttribute( Constants.POB ).equals("") || !gui.getSubjectDirectoryAttribute( Constants.COC ).equals("") )
        {
        	Vector<Attribute> v = new Vector<>();            	
        	
        	if ( !gui.getDateOfBirth().equals("") )
        	{
        		try {
        			SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd");
            		Date dateOfBirthDate = simpleDateFormat.parse( gui.getDateOfBirth() );
            		v.add(new Attribute(BCStyle.DATE_OF_BIRTH, new DERSet(new Time(dateOfBirthDate))));
        		} catch( Exception e ) {
        			if ( MyCode.DEBUG )
        				e.printStackTrace();
        		}
        	};
            
        	if ( !gui.getSubjectDirectoryAttribute( Constants.POB ).equals("") )
        		v.add(new Attribute(BCStyle.PLACE_OF_BIRTH, new DERSet((ASN1Encodable) new DEROctetString( gui.getSubjectDirectoryAttribute( Constants.POB ).getBytes() ))));
        	
        	if ( !gui.getSubjectDirectoryAttribute( Constants.COC ).equals("") )
        		v.add(new Attribute(BCStyle.COUNTRY_OF_CITIZENSHIP, new DERSet(new DEROctetString( gui.getSubjectDirectoryAttribute( Constants.COC ).getBytes() ))));
        	
        	if ( !gui.getGender().equals("") )
        		v.add(new Attribute(BCStyle.GENDER, new DERSet(new DEROctetString( gui.getGender().getBytes() ))));
        	
        	
        	SubjectDirectoryAttributes sda = new SubjectDirectoryAttributes(v);            	
        	lst.add( new Extension( new ASN1ObjectIdentifier( Extension.subjectDirectoryAttributes.getId() ), critical[1], sda.toASN1Primitive().getEncoded() ) );            	
        };
		
		// Return extensions.
		return lst.toArray(new Extension[lst.size()]);
	}
}
