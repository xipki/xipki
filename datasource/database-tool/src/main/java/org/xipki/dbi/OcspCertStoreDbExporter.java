package org.xipki.dbi;

import java.io.File;
import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.database.api.DataSource;
import org.xipki.dbi.ocsp.jaxb.CertStoreType;
import org.xipki.dbi.ocsp.jaxb.CertStoreType.Certprofiles;
import org.xipki.dbi.ocsp.jaxb.CertStoreType.CertsFiles;
import org.xipki.dbi.ocsp.jaxb.CertStoreType.Issuers;
import org.xipki.dbi.ocsp.jaxb.CertType;
import org.xipki.dbi.ocsp.jaxb.CertprofileType;
import org.xipki.dbi.ocsp.jaxb.CertsType;
import org.xipki.dbi.ocsp.jaxb.IssuerType;
import org.xipki.dbi.ocsp.jaxb.ObjectFactory;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

class OcspCertStoreDbExporter extends DbPorter{
	
	@SuppressWarnings("unused")
	private static final Logger LOG = LoggerFactory.getLogger(OcspCertStoreDbExporter.class);
	private final Marshaller marshaller;
	private final int COUNT_CERTS_IN_ONE_FILE  = 100;

	OcspCertStoreDbExporter(DataSource dataSource, Marshaller marshaller, String baseDir) 
			throws SQLException, PasswordResolverException, IOException
	{
		super(dataSource, baseDir);
		ParamChecker.assertNotNull("marshaller", marshaller);
		this.marshaller = marshaller;
	}
	
	public void export() throws Exception
	{
		CertStoreType certstore = new CertStoreType();
		certstore.setVersion(VERSION);

		certstore.setIssuers(export_issuer());
		certstore.setCertprofiles(export_certprofile());
		certstore.setCertsFiles(export_cert());
		
		JAXBElement<CertStoreType> root = new ObjectFactory().createCertStore(certstore);
		marshaller.marshal(root, new File(baseDir + File.separator + FILENAME_OCSP_CertStore));
	}

	private Issuers export_issuer()
	throws SQLException
	{
		Issuers issuers = new Issuers();
				
		Statement stmt = null;
		try{
			stmt = createStatement();
			
			String sql = "SELECT id, subject," + 
					" sha1_fp_name, sha1_fp_key," +
					" sha224_fp_name, sha224_fp_key," +
					" sha256_fp_name, sha256_fp_key," +
					" sha384_fp_name, sha384_fp_key," +
					" sha512_fp_name, sha512_fp_key," +
					" sha1_fp_cert, cert" +
					" FROM issuer";
			
			ResultSet rs = stmt.executeQuery(sql);		

			while(rs.next()){
				int id = rs.getInt("id");
				String subject = rs.getString("subject");
				String sha1_fp_cert = rs.getString("sha1_fp_cert");
				String cert = rs.getString("cert");
				String sha1_fp_name   = rs.getString("sha1_fp_name");
				String sha1_fp_key    = rs.getString("sha1_fp_key");
				String sha224_fp_name = rs.getString("sha224_fp_name");
				String sha224_fp_key  = rs.getString("sha224_fp_key");
				String sha256_fp_name = rs.getString("sha256_fp_name");
				String sha256_fp_key  = rs.getString("sha256_fp_key");
				String sha384_fp_name = rs.getString("sha384_fp_name");
				String sha384_fp_key  = rs.getString("sha384_fp_key");
				String sha512_fp_name = rs.getString("sha512_fp_name");
				String sha512_fp_key  = rs.getString("sha512_fp_key");

				IssuerType issuer = new IssuerType();
				issuer.setId(id);
				issuer.setSubject(subject);
				issuer.setSha1FpCert(sha1_fp_cert);
				issuer.setCert(cert);
				issuer.setSha1FpName(sha1_fp_name);
				issuer.setSha1FpKey(sha1_fp_key);
				issuer.setSha224FpName(sha224_fp_name);
				issuer.setSha224FpKey(sha224_fp_key);
				issuer.setSha256FpName(sha256_fp_name);
				issuer.setSha256FpKey(sha256_fp_key);
				issuer.setSha384FpName(sha384_fp_name);
				issuer.setSha384FpKey(sha384_fp_key);
				issuer.setSha512FpName(sha512_fp_name);
				issuer.setSha512FpKey(sha512_fp_key);
				
				issuers.getIssuer().add(issuer);
			}
			
			rs.close();
			rs = null;
		}finally
		{
			closeStatement(stmt);
		}

		return issuers;
	}

	private Certprofiles export_certprofile()
	throws SQLException
	{
		Certprofiles certprofiles = new Certprofiles();
				
		Statement stmt = null;
		try{
			stmt = createStatement();
			String sql = "SELECT id, name"
					+ " FROM certprofile";
			ResultSet rs = stmt.executeQuery(sql);		

			while(rs.next()){
				int id = rs.getInt("id");
				String name = rs.getString("name");

				CertprofileType info = new CertprofileType();
				info.setId(id);
				info.setName(name);
				
				certprofiles.getCertprofile().add(info);
			}
			
			rs.close();
			rs = null;
		}finally
		{
			closeStatement(stmt);
		}

		return certprofiles;
	}

	private CertsFiles export_cert()
	throws SQLException, IOException, JAXBException
	{	
		CertsFiles certsFiles = new CertsFiles();
	
		String certSql = "SELECT id, issuer_id, serial, certprofile_id," +
				" subject, last_update, notbefore, notafter," +
				" revocated, rev_reason, rev_time, rev_invalidity_time " +
				" FROM cert" +
				" WHERE id > ? AND id < ?";		

		String certhashSql = "SELECT sha1_fp, sha224_fp, sha256_fp, sha384_fp, sha512_fp" +
				" FROM certhash WHERE cert_id = ?";

		String rawCertSql = "SELECT cert FROM rawcert WHERE cert_id = ?";
		
		PreparedStatement certPs = prepareStatement(certSql);
		PreparedStatement certhashPs = prepareStatement(certhashSql);
		PreparedStatement rawCertPs = prepareStatement(rawCertSql);
		
		File certDir = new File(baseDir, "CERT");
		
		final int minCertId = getMinCertId();
		final int maxCertId = getMaxCertId();
		
		final ObjectFactory objFact = new ObjectFactory();
		
		int numCertInCurrentFile = 0;
		int startIdInCurrentFile = minCertId;
		CertsType certsInCurrentFile = new CertsType();
		
		final int n = 100;
		try{
			for(int i = minCertId; i <= maxCertId; i += n)
			{
				certPs.setInt(1, i - 1);
				certPs.setInt(2, i + n + 1);

				ResultSet rs = certPs.executeQuery();		

				while(rs.next()){
					int id = rs.getInt("id");
					int issuer_id = rs.getInt("issuer_id");
					String serial = rs.getString("serial");
					int certprofile_id = rs.getInt("certprofile_id");
					String subject = rs.getString("subject");
					String last_update = rs.getString("last_update");
					String notbefore = rs.getString("notbefore");
					String notafter = rs.getString("notafter");
					boolean revocated = rs.getBoolean("revocated");
					String rev_reason = rs.getString("rev_reason");
					String rev_time = rs.getString("rev_time");
					String rev_invalidity_time = rs.getString("rev_invalidity_time");

					String sha1_fp_cert;
					String sha224_fp_cert;
					String sha256_fp_cert;
					String sha384_fp_cert;
					String sha512_fp_cert;

					certhashPs.setInt(1, id);
					ResultSet certhashRs = certhashPs.executeQuery();
					try{
						certhashRs.next();
						sha1_fp_cert = certhashRs.getString("sha1_fp");
						sha224_fp_cert = certhashRs.getString("sha224_fp");
						sha256_fp_cert = certhashRs.getString("sha256_fp");
						sha384_fp_cert = certhashRs.getString("sha384_fp");
						sha512_fp_cert = certhashRs.getString("sha512_fp");
					}finally
					{
						certhashRs.close();
					}

					rawCertPs.setInt(1, id);
					ResultSet rawCertRs = rawCertPs.executeQuery();
					try{
						rawCertRs.next();
						String b64Cert = rawCertRs.getString("cert");
						IoCertUtil.save(new File(certDir, sha1_fp_cert), Base64.decode(b64Cert));
					}finally
					{
						rawCertRs.close();
					}

					CertType cert = new CertType();

					cert.setId(id);
					cert.setIssuerId(issuer_id);
					cert.setSerial(serial);
					cert.setCertprofileId(certprofile_id);
					cert.setSubject(subject);
					cert.setLastUpdate(last_update);
					cert.setNotbefore(notbefore);
					cert.setNotafter(notafter);
					cert.setRevocated(revocated);
					cert.setRevReason(rev_reason);
					cert.setRevTime(rev_time);
					cert.setRevInvalidityTime(rev_invalidity_time);
					cert.setSha1FpCert(sha1_fp_cert);
					cert.setSha224FpCert(sha224_fp_cert);
					cert.setSha256FpCert(sha256_fp_cert);
					cert.setSha384FpCert(sha384_fp_cert);
					cert.setSha512FpCert(sha512_fp_cert);
					cert.setCertFile(DIRNAME_CERT + File.separator + sha1_fp_cert);

					if(certsInCurrentFile.getCert().isEmpty())
					{
						startIdInCurrentFile = id;
					}
					
					certsInCurrentFile.getCert().add(cert);
					numCertInCurrentFile ++;
					
					if(numCertInCurrentFile == COUNT_CERTS_IN_ONE_FILE)
					{
						String fn = PREFIX_FILENAME_CERTS + startIdInCurrentFile + ".xml";						
						marshaller.marshal(objFact.createCerts(certsInCurrentFile), 
								new File(baseDir + File.separator + fn));
						
						certsFiles.getCertsFile().add(fn);
						
						certsInCurrentFile = new CertsType();
						numCertInCurrentFile = 0;
					}
				}
			}
			
			if(numCertInCurrentFile > 0)
			{
				String fn = "certs-" + startIdInCurrentFile + ".xml";						
				marshaller.marshal(objFact.createCerts(certsInCurrentFile), 
						new File(baseDir + File.separator + fn));
				
				certsFiles.getCertsFile().add(fn);
			}

		}finally
		{
			closeStatement(certPs);
			closeStatement(certhashPs);
			closeStatement(rawCertPs);
		}

		
		return certsFiles;
	}

	private int getMinCertId()
	throws SQLException
	{
		Statement stmt = null;
		try{
			stmt = createStatement();
			final String sql = "SELECT min(id) FROM cert";
			ResultSet rs = stmt.executeQuery(sql);
			
			rs.next();
			int minCertId = rs.getInt(1);
			
			rs.close();
			rs = null;
			
			return minCertId;
		}finally
		{
			closeStatement(stmt);
		}
	}

	private int getMaxCertId()
	throws SQLException
	{
		Statement stmt = null;
		try{
			stmt = createStatement();
			final String sql = "SELECT max(id) FROM cert";
			ResultSet rs = stmt.executeQuery(sql);
			
			rs.next();
			int maxCertId = rs.getInt(1);
			
			rs.close();
			rs = null;
			
			return maxCertId;
		}finally
		{
			closeStatement(stmt);
		}
	}

	
}