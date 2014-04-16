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
	private final Marshaller marshaller;
	private final int COUNT_CERTS_IN_ONE_FILE  = 1000;

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
			
			String sql = "SELECT id, cert FROM issuer";
			
			ResultSet rs = stmt.executeQuery(sql);		

			while(rs.next()){
				int id = rs.getInt("id");
				String cert = rs.getString("cert");

				IssuerType issuer = new IssuerType();
				issuer.setId(id);
				issuer.setCert(cert);
				
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
			String sql = "SELECT id, name FROM certprofile";
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
	
		String certSql = "SELECT id, issuer_id, certprofile_id, last_update," +
				" revocated, rev_reason, rev_time, rev_invalidity_time " +
				" FROM cert" +
				" WHERE id > ? AND id < ?";

		String rawCertSql = "SELECT cert FROM rawcert WHERE cert_id = ?";
		
		PreparedStatement certPs = prepareStatement(certSql);
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
					int certprofile_id = rs.getInt("certprofile_id");
					String last_update = rs.getString("last_update");
					boolean revocated = rs.getBoolean("revocated");
					String rev_reason = rs.getString("rev_reason");
					String rev_time = rs.getString("rev_time");
					String rev_invalidity_time = rs.getString("rev_invalidity_time");

					rawCertPs.setInt(1, id);
					
					String sha1_fp_cert;
					
					ResultSet rawCertRs = rawCertPs.executeQuery();
					try{
						rawCertRs.next();
						String b64Cert = rawCertRs.getString("cert");
						byte[] cert = Base64.decode(b64Cert);
						sha1_fp_cert = IoCertUtil.sha1sum(cert);
						IoCertUtil.save(new File(certDir, sha1_fp_cert), cert);
					}finally
					{
						rawCertRs.close();
					}

					CertType cert = new CertType();

					cert.setId(id);
					cert.setIssuerId(issuer_id);
					cert.setCertprofileId(certprofile_id);
					cert.setLastUpdate(last_update);
					cert.setRevocated(revocated);
					cert.setRevReason(rev_reason);
					cert.setRevTime(rev_time);
					cert.setRevInvalidityTime(rev_invalidity_time);
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