package org.xipki.dbi;

import java.io.File;
import java.io.IOException;
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
import org.xipki.dbi.ocsp.jaxb.CertStoreType;
import org.xipki.dbi.ocsp.jaxb.CertStoreType.Certprofiles;
import org.xipki.dbi.ocsp.jaxb.CertStoreType.CertsFiles;
import org.xipki.dbi.ocsp.jaxb.CertStoreType.Issuers;
import org.xipki.dbi.ocsp.jaxb.CertType;
import org.xipki.dbi.ocsp.jaxb.CertprofileType;
import org.xipki.dbi.ocsp.jaxb.CertsType;
import org.xipki.dbi.ocsp.jaxb.IssuerType;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

class OcspCertStoreDbImporter extends DbPorter{
	private final Unmarshaller unmarshaller;
	private final SHA1Digest sha1md = new SHA1Digest();
	
	OcspCertStoreDbImporter(DataSource dataSource, Unmarshaller unmarshaller, String srcDir) 
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
				unmarshaller.unmarshal(new File(baseDir + File.separator + FILENAME_OCSP_CertStore));
		CertStoreType certstore = root.getValue();
		
		import_issuer(certstore.getIssuers());
		import_certprofile(certstore.getCertprofiles());
		import_cert(certstore.getCertsFiles());
	}

	private void import_issuer(Issuers issuers)
			throws SQLException
	{
		final String SQL_ADD_CAINFO =
		    	"INSERT INTO issuer (" +
		    	" id, subject," +
		    	" sha1_fp_name, sha1_fp_key," +
		    	" sha224_fp_name, sha224_fp_key," +
		    	" sha256_fp_name, sha256_fp_key," +
		    	" sha384_fp_name, sha384_fp_key," +
		    	" sha512_fp_name, sha512_fp_key," +
		    	" sha1_fp_cert, cert" + 
				" ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
		
		PreparedStatement ps = prepareStatement(SQL_ADD_CAINFO);

		try{
			for(IssuerType issuer : issuers.getIssuer())
			{
				int idx = 1;
				ps.setInt   (idx++, issuer.getId());
				ps.setString(idx++, issuer.getSubject());
				ps.setString(idx++, issuer.getSha1FpName());
				ps.setString(idx++, issuer.getSha1FpKey());
				ps.setString(idx++, issuer.getSha224FpName());
				ps.setString(idx++, issuer.getSha224FpKey());
				ps.setString(idx++, issuer.getSha256FpName());
				ps.setString(idx++, issuer.getSha256FpKey());
				ps.setString(idx++, issuer.getSha384FpName());
				ps.setString(idx++, issuer.getSha384FpKey());
				ps.setString(idx++, issuer.getSha512FpName());
				ps.setString(idx++, issuer.getSha512FpKey());
				ps.setString(idx++, issuer.getSha1FpCert());
				ps.setString(idx++, issuer.getCert());
				
				ps.execute();
			}
		}finally {
			closeStatement(ps);
		}
	}
	
	private void import_certprofile(Certprofiles certprofiles)
			throws SQLException
	{
		final String sql = "INSERT INTO certprofile (id, name) VALUES (?, ?)";
		
		PreparedStatement ps = prepareStatement(sql);

		try{
			for(CertprofileType info : certprofiles.getCertprofile())
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
		    	"INSERT INTO cert (" + 
		    	" id, issuer_id, serial, certprofile_id," +
				" subject, last_update, notbefore, notafter," +
				" revocated, rev_reason, rev_time, rev_invalidity_time)" +
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

		final String SQL_ADD_CERTHASH = "INSERT INTO certhash (" +
				"cert_id, sha1_fp, sha224_fp, sha256_fp, sha384_fp, sha512_fp)" +
				" VALUES (?, ?, ?, ?, ?, ?)";

		final String SQL_ADD_RAWCERT = "INSERT INTO rawcert (cert_id, cert) VALUES (?, ?)";

		PreparedStatement ps_cert = prepareStatement(SQL_ADD_CERT);
		PreparedStatement ps_certhash = prepareStatement(SQL_ADD_CERTHASH);
		PreparedStatement ps_rawcert = prepareStatement(SQL_ADD_RAWCERT);

		try{
			for(CertType cert : certs.getCert())
			{
				// cert
				int idx = 1;
				ps_cert.setInt   (idx++, cert.getId());
				ps_cert.setInt   (idx++, cert.getIssuerId());
				ps_cert.setString(idx++, cert.getSerial());
				ps_cert.setInt   (idx++, cert.getCertprofileId());
				ps_cert.setString(idx++, cert.getSubject());
				ps_cert.setString(idx++, cert.getLastUpdate());
				ps_cert.setString(idx++, cert.getNotbefore());
				ps_cert.setString(idx++, cert.getNotafter());
				ps_cert.setBoolean(idx++, cert.isRevocated());
				ps_cert.setString(idx++, cert.getRevReason());
				ps_cert.setString(idx++, cert.getRevTime());
				ps_cert.setString(idx++, cert.getRevInvalidityTime());
				
				ps_cert.executeUpdate();

				// certhash
				idx = 1;
				ps_certhash.setInt(idx++, cert.getId());
				ps_certhash.setString(idx++, cert.getSha1FpCert());
				ps_certhash.setString(idx++, cert.getSha224FpCert());
				ps_certhash.setString(idx++, cert.getSha256FpCert());
				ps_certhash.setString(idx++, cert.getSha384FpCert());
				ps_certhash.setString(idx++, cert.getSha512FpCert());
				
				ps_certhash.executeUpdate();
				
				// rawcert
				String filename = baseDir + File.separator + cert.getCertFile();
				byte[] encodedCert = IoCertUtil.read(filename);
				
				ps_rawcert.setInt   (1, cert.getId());
				ps_rawcert.setString(2, Base64.toBase64String(encodedCert));   
				
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