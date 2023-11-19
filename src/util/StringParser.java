package util;

import java.io.File;
import java.security.cert.X509Certificate;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

import implementation.MyCode;
import keystore.LocalKeyStore;
import storage.StorageElement;
import x509.v3.GuiV3;

public class StringParser 
{
	
	/**
	 * Gets subject info in format.
	 * 
	 * @param alias - name of the keyStore.
	 * @return formatted text.
	 */
	public static String getSubjectInfo( String alias )
	{
		StringBuilder str = new StringBuilder();
		try {			
			X509Certificate cert = LocalKeyStore.getInstance().getCertificate(alias);
			X500Principal pr = cert.getSubjectX500Principal();
			LdapName ldapDN = new LdapName(pr.getName());
			int i = 0;
			for(Rdn rdn: ldapDN.getRdns()) 
			{
				if ( i>0 )
					str.append(",");
				String val = rdn.getValue().toString();
				switch( rdn.getType() )
				{
				case "C":
					str.append("C="+val);
					break;
				case "ST":
					str.append("ST="+val);
					break;
				case "O":
					str.append("O="+val);
					break;
				case "CN":
					str.append("CN="+val);
					break;
				case "OU":
					str.append("OU="+val);
					break;
				case "L":
					str.append("L="+val);
					break;
				};	
				i++;
			};	
		} catch (Exception e) {
			if ( MyCode.DEBUG )
				e.printStackTrace();
		}
		return str.toString();
	}
	
	/**
	 * Gets subject info in format.
	 * 
	 * @param alias - name of the keyStore.
	 * @return formatted text.
	 */
	public static String getIssuerInfo( String alias )
	{
		StringBuilder str = new StringBuilder();
		try {						
			X509Certificate cert = LocalKeyStore.getInstance().getCertificate(alias);	
			X500Principal pr = cert.getIssuerX500Principal();
			LdapName ldapDN = new LdapName(pr.getName());
			int i = 0;
			for(Rdn rdn: ldapDN.getRdns()) 
			{
				if ( i>0 )
					str.append(",");
				String val = rdn.getValue().toString();
				switch( rdn.getType() )
				{
				case "C":
					str.append("C="+val);
					break;
				case "ST":
					str.append("ST="+val);
					break;
				case "O":
					str.append("O="+val);
					break;
				case "CN":
					str.append("CN="+val);
					break;
				case "OU":
					str.append("OU="+val);	
					break;
				case "L":
					str.append("L="+val);
					break;
				};	
				i++;
			};	
		} catch (Exception e) {
			if ( MyCode.DEBUG )
				e.printStackTrace();			
		}
		return str.toString();
	}
	
	/**
	 * Gets subject info in format.
	 * 
	 * @param elem - Issuer's principal.
	 * @return formatted text.
	 */
	public static String getIssuerInfo( X500Principal elem )
	{
		StringBuilder str = new StringBuilder();
		try {		
			LdapName ldapDN = new LdapName( elem.getName() );
			int i = 0;
			for(Rdn rdn: ldapDN.getRdns()) 
			{
				if ( i>0 )
					str.append(",");
				String val = rdn.getValue().toString();
				switch( rdn.getType() )
				{
				case "C":
					str.append("C="+val);
					break;
				case "ST":
					str.append("ST="+val);
					break;
				case "O":
					str.append("O="+val);
					break;
				case "CN":
					str.append("CN="+val);
					break;
				case "OU":
					str.append("OU="+val);	
					break;
				case "L":
					str.append("L="+val);
					break;
				};	
				i++;
			};	
		} catch (Exception e) {
			if ( MyCode.DEBUG )
				e.printStackTrace();			
		}
		return str.toString();
	}
	
	/**
	 * Gets subject's data.
	 * 
	 * @return subject's data.
	 */
	public static String readSubjectInfo( GuiV3 gui )
	{
		StringBuilder str = new StringBuilder();		
		String s = null;
		boolean first = false;
		
		if ( !(s = gui.getSubjectCountry()).equals("") )
		{
			str.append("C=" + s);
			first = true;
		};
		
		if ( !(s = gui.getSubjectState()).equals("") )
		{
			if ( first ) 
				str.append(',');
			str.append("ST=" + s);
			first = true;
		};
		
		if ( !(s = gui.getSubjectLocality()).equals("") )
		{
			if ( first ) 
				str.append(',');
			str.append("L=" + s);
			first = true;
		};			
		
		if ( !(s = gui.getSubjectOrganization()).equals("") )
		{
			if ( first ) 
				str.append(',');
			str.append("O=" + s);
			first = true;
		}
		
		if ( !(s = gui.getSubjectOrganizationUnit()).equals("") )
		{
			if ( first ) 
				str.append(',');
			str.append("OU= " + s);
			first = true;
		}			
		
		if ( first ) 
			str.append(',');
		str.append("CN=" + gui.getSubjectCommonName());		
		
		return str.toString();
	}
	
	public static String getSubjectInfo( String country, String state, String locality, String organization, String ou, String cn, String sa )
	{
		StringBuilder str = new StringBuilder();		
		boolean first = false;
		
		if ( country != null && !country.equals("") )
		{
			str.append("C=" + country);
			first = true;
		};
		
		if ( state != null && !state.equals("") )
		{
			if ( first ) 
				str.append(',');
			str.append("ST=" + state);
			first = true;
		};
		
		if ( locality != null && !locality.equals("") )
		{
			if ( first ) 
				str.append(',');
			str.append("L=" + locality);
			first = true;
		};			
		
		if ( organization != null && !organization.equals("") )
		{
			if ( first ) 
				str.append(',');
			str.append("O=" + organization);
			first = true;
		}
		
		if ( ou != null && !ou.equals("") )
		{
			if ( first ) 
				str.append(',');
			str.append("OU= " + ou);
			first = true;
		}			
		
		if ( first ) 
			str.append(',');
		str.append("CN=" +  cn );
		
		str.append(',');
		str.append( "SA=" + sa );
		
		return str.toString();
	}
	
	/**
	 * Gets file's extension.
	 * 
	 * @param file - Given file.
	 * @return extension of the file.
	 */
	public static String getFileExtension(File file) 
	{
	    String name = file.getName();
	    int lastIndexOf = name.lastIndexOf(".");
	    if (lastIndexOf == -1) {
	        return ""; // empty extension
	    }
	    return name.substring(lastIndexOf+1);
	}
}
