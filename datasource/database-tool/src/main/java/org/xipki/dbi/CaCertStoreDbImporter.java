package org.xipki.dbi;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.database.api.DataSource;
import org.xipki.dbi.ca.jaxb.CainfoType;
import org.xipki.dbi.ca.jaxb.CertStoreType;
import org.xipki.dbi.ca.jaxb.CertStoreType.Cainfos;
import org.xipki.dbi.ca.jaxb.CertStoreType.Certprofileinfos;
import org.xipki.dbi.ca.jaxb.CertStoreType.CertsFiles;
import org.xipki.dbi.ca.jaxb.CertStoreType.Crls;
import org.xipki.dbi.ca.jaxb.CertStoreType.Requestorinfos;
import org.xipki.dbi.ca.jaxb.CertStoreType.Users;
import org.xipki.dbi.ca.jaxb.CertType;
import org.xipki.dbi.ca.jaxb.CertprofileinfoType;
import org.xipki.dbi.ca.jaxb.CertsType;
import org.xipki.dbi.ca.jaxb.CrlType;
import org.xipki.dbi.ca.jaxb.RequestorinfoType;
import org.xipki.dbi.ca.jaxb.UserType;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

class CaCertStoreDbImporter extends DbPorter{
	private final Unmarshaller unmarshaller;
	private final SHA1Digest sha1md = new SHA1Digest();
	
	CaCertStoreDbImporter(DataSource dataSource, Unmarshaller unmarshaller, String srcDir) 
			throws SQLException, PasswordResolverException, IOException
	{
		super(dataSource, srcDir);
		ParamChecker.assertNotNull("unmarshaller", unmarshaller);
		this.unmarshaller = unmarshaller;		
	}

	public void importToDB() throws Exception
	{
		@SuppressWarnings("unchecked")
		JAXBElement<CertStoreType> root = (JAXBElement<CertStoreType>) 
				unmarshaller.unmarshal(new File(baseDir + File.separator + FILENAME_CA_CertStore));
		CertStoreType certstore = root.getValue();
		
		import_cainfo(certstore.getCainfos());
		import_requestorinfo(certstore.getRequestorinfos());
		import_certprofileinfo(certstore.getCertprofileinfos());
		import_user(certstore.getUsers());
		import_crl(certstore.getCrls());
		import_cert(certstore.getCertsFiles());
	}

	private void import_cainfo(Cainfos cainfos)
			throws SQLException
	{
		final String SQL_ADD_CAINFO =
		    	"INSERT INTO cainfo" +
		    	" (id, subject, sha1_fp_cert, cert)" + 
				" VALUES (?, ?, ?, ?)";
		
		PreparedStatement ps = prepareStatement(SQL_ADD_CAINFO);

		try{
			for(CainfoType info : cainfos.getCainfo())
			{
				int idx = 1;
				ps.setInt   (idx++, info.getId());
				ps.setString(idx++, info.getSubject());
				ps.setString(idx++, info.getSha1FpCert());
				ps.setString(idx++, info.getCert());
				
				ps.execute();
			}
		}finally {
			closeStatement(ps);
		}
	}
	
	private void import_requestorinfo(Requestorinfos requestorinfos)
			throws SQLException
	{
		final String sql = "INSERT INTO requestorinfo (id, subject, sha1_fp_cert, cert) VALUES (?, ?, ?, ?)";
		
		PreparedStatement ps = prepareStatement(sql);

		try{
			for(RequestorinfoType info : requestorinfos.getRequestorinfo())
			{
				int idx = 1;
				ps.setInt   (idx++, info.getId());
				ps.setString(idx++, info.getSubject());
				ps.setString(idx++, info.getSha1FpCert());
				ps.setString(idx++, info.getCert());
				
				ps.execute();
			}
		}finally {
			closeStatement(ps);
		}
	}

	private void import_certprofileinfo(Certprofileinfos certprofileinfos)
			throws SQLException
	{
		final String sql = "INSERT INTO certprofileinfo (id, name) VALUES (?, ?)";
		
		PreparedStatement ps = prepareStatement(sql);

		try{
			for(CertprofileinfoType info : certprofileinfos.getCertprofileinfo())
			{
				int idx = 1;
				ps.setInt   (idx++, info.getId());
				ps.setString(idx++, info.getName());
				
				ps.execute();
			}
		}finally {
			closeStatement(ps);
		}		
	}

	private void import_user(Users users)
			throws SQLException
	{
		final String sql = "INSERT INTO user (id, name) VALUES (?, ?)";
		
		PreparedStatement ps = prepareStatement(sql);

		try{
			for(UserType user : users.getUser())
			{
				int idx = 1;
				ps.setInt   (idx++, user.getId());
				ps.setString(idx++, user.getName());
				
				ps.execute();
			}
		}finally {
			closeStatement(ps);
		}	
	}

	private void import_crl(Crls crls)
			throws SQLException, IOException
	{
		final String sql = "INSERT INTO crl (cainfo_id, crl_number, thisUpdate, nextUpdate, crl) VALUES (?, ?, ?, ?, ?)";

		PreparedStatement ps = prepareStatement(sql);

		try{
			for(CrlType crl : crls.getCrl())
			{
				int idx = 1;			
				ps.setInt   (idx++, crl.getCainfoId());
				ps.setString(idx++, crl.getCrlNumber());
				ps.setString(idx++, crl.getThisUpdate());
				ps.setString(idx++, crl.getNextUpdate());

				String filename = baseDir + File.separator + crl.getCrlFile();
				byte[] encodedCrl = IoCertUtil.read(filename);
				InputStream is = new ByteArrayInputStream(encodedCrl);
				ps.setBlob(idx++, is);
				
				ps.executeUpdate();
			}
		}finally {
			closeStatement(ps);
		}
	}

	private void import_cert(CertsFiles certsfiles)
			throws SQLException, JAXBException, IOException
	{
		for(String certsFile : certsfiles.getCertsFile())
		{
			@SuppressWarnings("unchecked")
			JAXBElement<CertsType> root = (JAXBElement<CertsType>) 
					unmarshaller.unmarshal(new File(baseDir + File.separator + certsFile));
			do_import_cert(root.getValue());
		}
	}
	
	private void do_import_cert(CertsType certs)
		throws SQLException, IOException
	{
		final String SQL_ADD_CERT = 
		    	"INSERT INTO cert " + 
		    	"(id, last_update, serial, subject,"
		    	+ " notbefore, notafter, revocated, rev_reason, rev_time, rev_invalidity_time,"
		    	+ " certprofileinfo_id, cainfo_id,"
		    	+ " requestorinfo_id, user_id, sha1_fp_pk, sha1_fp_subject)" + 
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

		final String SQL_ADD_RAWCERT = "INSERT INTO rawcert (cert_id, sha1_fp, cert) VALUES (?, ?, ?)";

		PreparedStatement ps_cert = prepareStatement(SQL_ADD_CERT);
		PreparedStatement ps_rawcert = prepareStatement(SQL_ADD_RAWCERT);

		try{
			for(CertType cert : certs.getCert())
			{
				// cert
				int idx = 1;
				ps_cert.setInt   (idx++, cert.getId());
				ps_cert.setString(idx++, cert.getLastUpdate());
				ps_cert.setString(idx++, cert.getSerial());
				ps_cert.setString(idx++, cert.getSubject());
				ps_cert.setString(idx++, cert.getNotbefore());
				ps_cert.setString(idx++, cert.getNotafter());
				ps_cert.setBoolean(idx++, cert.isRevocated());
				ps_cert.setString(idx++, cert.getRevReason());
				ps_cert.setString(idx++, cert.getRevTime());
				ps_cert.setString(idx++, cert.getRevInvalidityTime());
				ps_cert.setString(idx++, cert.getCertprofileinfoId());
				ps_cert.setString(idx++, cert.getCainfoId());
				ps_cert.setString(idx++, cert.getRequestorinfoId());
				ps_cert.setString(idx++, cert.getUserId());
				ps_cert.setString(idx++, cert.getSha1FpPk());
				
				String sha1FpSubject = cert.getSha1FpCert();
				if(sha1FpSubject == null || sha1FpSubject.length() < 20)
				{
					sha1FpSubject = fp_canonicalized_name(cert.getSubject());
				}
				ps_cert.setString(idx++, cert.getSha1FpSubject());

				ps_cert.executeUpdate();

				// rawcert
				String filename = baseDir + File.separator + cert.getCertFile();
				byte[] encodedCert = IoCertUtil.read(filename);
				
				ps_rawcert.setInt   (1, cert.getId());
				ps_rawcert.setString(2, cert.getSha1FpCert());
				ps_rawcert.setString(3, Base64.toBase64String(encodedCert));   
				
				ps_rawcert.executeUpdate();
			}
		}finally {
			closeStatement(ps_cert);
			closeStatement(ps_rawcert);
		}

	}

	/**
	 * First canonicalized the name, and then compute the SHA-1 fingerprint over the 
	 * canonicalized subject string.
	 * @param name
	 * @return
	 */
	String fp_canonicalized_name(String dirName)
	{
		X500Name name = new X500Name(dirName);
		
		ASN1ObjectIdentifier[] _types = name.getAttributeTypes();
		int n = _types.length;
		List<String> types = new ArrayList<String>(n);
		for(ASN1ObjectIdentifier type : _types)
		{
			types.add(type.getId());
		}
		
		Collections.sort(types);
		
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < n; i++)
		{
			String type = types.get(i);
			if(i > 0)
			{
				sb.append(",");
			}
			sb.append(type).append("=");
			RDN[] rdns = name.getRDNs(new ASN1ObjectIdentifier(type));
			
			for(int j = 0; j < rdns.length; j++)
			{
				if(j > 0)
				{
					sb.append(";");
				}
				RDN rdn = rdns[j];
				String textValue = IETFUtils.valueToString(rdn.getFirst().getValue());
				sb.append(textValue);				
			}
		}
		
		String canonicalizedName = sb.toString();
		byte[] encoded;
		try {
			encoded = canonicalizedName.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			encoded = canonicalizedName.getBytes();
		}
		
		synchronized (sha1md) {
			sha1md.reset();
			sha1md.update(encoded, 0, encoded.length);
			byte[] sha1fp = new byte[20];
			sha1md.doFinal(sha1fp, 0);
			
			return Hex.toHexString(sha1fp).toUpperCase();
		}
	}
	
}