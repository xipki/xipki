/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This work is part of XiPKI, owned by Lijun Liao (lijun.liao@gmail.com)
 *
 */

package org.xipki.ca.server.publisher;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.ca.server.X509Util;
import org.xipki.database.api.DataSource;

class CertStatusStoreQueryExecutor
{
	private static final Logger LOG = LoggerFactory.getLogger(CertStatusStoreQueryExecutor.class);
	
	private AtomicInteger cert_id;

	private final DataSource dataSource;

	private final IssuerStore issuerStore;
	private final CertprofileStore certprofileStore;
	
	private final HashCalculator hashCalculator;
	
	CertStatusStoreQueryExecutor(DataSource dataSource)
	throws SQLException, NoSuchAlgorithmException
	{
		this.dataSource = dataSource;
		this.hashCalculator = new HashCalculator();
		
        final String sql = "SELECT MAX(id) FROM cert";
        PreparedStatement ps = borrowPreparedStatement(sql);
        ResultSet rs = null;
        try{
        	rs = ps.executeQuery();
            rs.next();
            cert_id = new AtomicInteger(rs.getInt(1) + 1);            	
        } finally {
        	returnPreparedStatement(ps);
        	if(rs != null) {
        		rs.close();
        		rs = null;
        	}
        }

        this.issuerStore = initIssuerStore();
        this.certprofileStore = initCertprofileStore();
	}
	
	private IssuerStore initIssuerStore() 
	throws SQLException
	{
    	final String sql = "SELECT id, subject, sha1_fp_cert, cert FROM issuer";    	

        PreparedStatement ps = borrowPreparedStatement(sql);
        
        ResultSet rs = null;
		try{
			rs = ps.executeQuery();
			List<IssuerEntry> caInfos = new LinkedList<IssuerEntry>();
			while(rs.next()) {
				int id = rs.getInt("id");
				String subject = rs.getString("subject");
				String hexSha1Fp = rs.getString("sha1_fp_cert");
				String b64Cert = rs.getString("cert");
				
				IssuerEntry caInfoEntry = new IssuerEntry(id, subject, hexSha1Fp, b64Cert);
				caInfos.add(caInfoEntry);
			}
			
			return new IssuerStore(caInfos);
		}finally {
			returnPreparedStatement(ps);
        	if(rs != null) {
        		rs.close();
        		rs = null;
        	}
		}
	}
	
	private CertprofileStore initCertprofileStore() 
	throws SQLException
	{
    	final String sql = "SELECT id, name FROM certprofile";    	

        PreparedStatement ps = borrowPreparedStatement(sql);
        
        ResultSet rs = null;
		try{
			rs = ps.executeQuery();
			Map<String, Integer> entries = new HashMap<String, Integer>();
			
			while(rs.next()) {
				int id = rs.getInt("id");
				String name = rs.getString("name");
				entries.put(name, id);
			}
			
			return new CertprofileStore(entries);
		}finally {
			returnPreparedStatement(ps);
        	if(rs != null) {
        		rs.close();
        		rs = null;
        	}
		}
	}
	
	/**
	 * @throws SQLException if there is problem while accessing database.
	 * @throws NoSuchAlgorithmException 
	 * @throws CertificateEncodingException 
	 */
	void addCert(X509CertificateWithMetaInfo issuer,
			X509CertificateWithMetaInfo certificate,
			String certprofileName)
			throws SQLException, CertificateEncodingException
	{
		final String SQL_ADD_CERT = 
		    	"INSERT INTO cert " + 
		    	"(id, last_update, serial, subject,"
		    	+ " notbefore, notafter, revocated, certprofile_id, issuer_id)" + 
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

		PreparedStatement ps = borrowPreparedStatement(SQL_ADD_CERT);
		if(ps == null) {
			throw new SQLException("Cannot create prepared incert_cert statement");
		}			

		int certId = cert_id.getAndAdd(1);
		int certprofileId = getCertprofileId(certprofileName);
		
		try{
			int issuerId = getIssuerId(issuer);

			X509Certificate cert = certificate.getCert();
			int idx = 1;
			ps.setInt(idx++, certId);
			ps.setLong(idx++, System.currentTimeMillis()/1000);    			
			ps.setString(idx++, cert.getSerialNumber().toString());
			ps.setString(idx++, X509Util.canonicalizeName(cert.getSubjectX500Principal()));
			ps.setLong(idx++, cert.getNotBefore().getTime()/1000);
			ps.setLong(idx++, cert.getNotAfter().getTime()/1000);
			ps.setBoolean(idx++, false);    			
			ps.setInt(idx++, certprofileId);
			ps.setInt(idx++, issuerId);

			ps.executeUpdate();
		}finally {
			returnPreparedStatement(ps);
		}

		final String SQL_ADD_RAWCERT = "INSERT INTO rawcert (cert_id, cert) VALUES (?, ?)";

		ps = borrowPreparedStatement(SQL_ADD_RAWCERT);
		if(ps == null) {
			throw new SQLException("Cannot create prepared insert_raw_cert statement");
		}
    		
		byte[] encodedCert = certificate.getEncodedCert();
		try{
			int idx = 1;
			ps.setInt(idx++, certId);
			ps.setString(idx++, Base64.toBase64String(encodedCert));    			
			ps.executeUpdate();
		}finally {
			returnPreparedStatement(ps);
		}
		
		final String SQL_ADD_CERTHASH = "INSERT INTO certhash "
				+ " (cert_id, sha1_fp, sha224_fp, sha256_fp, sha384_fp, sha512_fp)"
				+ " VALUES (?, ?, ?, ?, ?, ?)";

		ps = borrowPreparedStatement(SQL_ADD_CERTHASH);
		if(ps == null) {
			throw new SQLException("Cannot create prepared insert_certhash statement");
		}
    		
		try{
			int idx = 1;
			ps.setInt(idx++, certId);
			ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA1,   encodedCert));
			ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA224, encodedCert));
			ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA256, encodedCert));
			ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA384, encodedCert));
			ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA512, encodedCert));
			ps.executeUpdate();
		}finally {
			returnPreparedStatement(ps);
		}
	}
	
	boolean revocateCert(X509Certificate cert, Date revocationTime, int revocationReason,
			Date invalidityTime)
	throws SQLException
	{
		return revocateCert(cert.getIssuerX500Principal(), cert.getSerialNumber(), revocationTime, 
				revocationReason, invalidityTime);
	}

	boolean revocateCert(X500Principal issuer, BigInteger serial, Date revocationTime, 
			int revocationReason, Date invalidityTime)
		throws SQLException
	{
		String issuerName = X500Name.getInstance(issuer.getEncoded()).toString();
		return revocateCert(issuerName, serial, revocationTime, revocationReason, invalidityTime);
	}
	
	boolean revocateCert(String issuer, BigInteger serial, Date revocationTime, 
		int revocationReason, Date invalidityTime)
	throws SQLException
	{
		Integer issuer_id = issuerStore.getIdForSubject(issuer);
		if(issuer_id == null) {
			LOG.warn("Could find the issuer.id for the issuer " + issuer);
			return false;
		}

		final String sql = "UPDATE cert" +
			    " SET last_update = ?, revocated = ?, rev_time = ?, rev_invalidity_time = ?, rev_reason = ?" +
			    " WHERE issuer_id = ? AND serial = ?";
			
		PreparedStatement ps = borrowPreparedStatement(sql);
		if(ps == null) {
			throw new SQLException("Cannot create prepared insert_raw_cert statement");
		}
    		
		try{
			int idx = 1;
			ps.setLong(idx++, new Date().getTime()/1000);				
			ps.setBoolean(idx++, true);
			ps.setLong(idx++, revocationTime.getTime()/1000);
			if(invalidityTime != null) {
				ps.setLong(idx++, invalidityTime.getTime()/1000);
			}else {
				ps.setNull(idx++, Types.BIGINT);
			}
			ps.setInt(idx++, revocationReason);
			ps.setInt(idx++, issuer_id.intValue());
			ps.setLong(idx++, serial.intValue());
			ps.executeUpdate();
			
			return true;
		}finally {
			returnPreparedStatement(ps);
		}
	}
	
	private int getCertprofileId(String certprofileName)
	throws SQLException
	{
		if(certprofileName == null)
		{
			return -1;
		}
		
		Integer id = certprofileStore.getId(certprofileName);
		if(id != null)
		{
			return id.intValue();
		}
		
		final String sql = "INSERT INTO certprofile (id, name) VALUES (?, ?)";
		
		PreparedStatement ps = borrowPreparedStatement(sql);
		if(ps == null) {
			throw new SQLException("Cannot create prepared insert_certprofile statement");
		}
	    
		id = certprofileStore.getNextFreeId();
		try{
			int idx = 1;
			ps.setInt(idx++, id.intValue());
			ps.setString(idx++, certprofileName);
			
			ps.execute();
			certprofileStore.addProfileEntry(certprofileName, id);
		}finally {
			returnPreparedStatement(ps);
		}		
		
		return id.intValue();
	}
	
	private int getIssuerId(X509CertificateWithMetaInfo issuerCert)
			throws SQLException, CertificateEncodingException
	{
		Integer id =  issuerStore.getIdForCert(issuerCert.getEncodedCert());

		if(id != null) {
			return id.intValue();
		}
		
		final String sql =
		    	"INSERT INTO issuer" +
		    	" (id, subject, "
		    	+ "sha1_fp_name, sha1_fp_key, "
		    	+ "sha224_fp_name, sha224_fp_key, "
		    	+ "sha256_fp_name, sha256_fp_key, "
		    	+ "sha384_fp_name, sha384_fp_key, "
		    	+ "sha512_fp_name, sha512_fp_key,"
		    	+ "sha1_fp_cert, cert)" + 
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
		
		String hexSha1FpCert = hashCalculator.hexHash(HashAlgoType.SHA1, issuerCert.getEncodedCert());
		
		PreparedStatement ps = borrowPreparedStatement(sql);
		if(ps == null) {
			throw new SQLException("Cannot create prepared insert_issuer statement");
		}
	    
		Certificate bcCert = Certificate.getInstance(issuerCert.getEncodedCert());
		byte[] encodedName;
		try {
			encodedName = bcCert.getSubject().getEncoded("DER");
		} catch (IOException e) {
			throw new CertificateEncodingException(e);
		}
		byte[] encodedKey = bcCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
		
		id = issuerStore.getNextFreeId();
		try{
			String b64Cert = Base64.toBase64String(issuerCert.getEncodedCert());
			String subject = X509Util.canonicalizeName(issuerCert.getCert().getSubjectX500Principal());
			int idx = 1;
			ps.setInt(idx++, id.intValue());
			ps.setString(idx++, subject);
			ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA1, encodedName));
			ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA1, encodedKey));
			ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA224, encodedName));
			ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA224, encodedKey));
			ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA256, encodedName));
			ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA256, encodedKey));
			ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA384, encodedName));
			ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA384, encodedKey));
			ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA512, encodedName));
			ps.setString(idx++, hashCalculator.hexHash(HashAlgoType.SHA512, encodedKey));			
			ps.setString(idx++, hexSha1FpCert);
			ps.setString(idx++, b64Cert);
			
			ps.execute();
			
			IssuerEntry newInfo = new IssuerEntry(id.intValue(), subject, hexSha1FpCert, b64Cert);
			issuerStore.addIdentityEntry(newInfo);
		}finally {
			returnPreparedStatement(ps);
		}		
		
		return id.intValue();
	}
		
	/**
	 * 
	 * @return the next idle preparedStatement, {@code null} will be returned
	 *         if no PreparedStament can be created within 5 seconds
	 * @throws SQLException
	 */
	private PreparedStatement borrowPreparedStatement(String sqlQuery) throws SQLException
	{
		PreparedStatement ps = null;
		Connection c = dataSource.getConnection(5000);
		if(c != null) {
			ps = c.prepareStatement(sqlQuery);
		}
		return ps;
	}
	
	private void returnPreparedStatement(PreparedStatement ps)
	{
		try{ 
    		Connection conn = ps.getConnection();
    		ps.close();
    		dataSource.returnConnection(conn);
		}catch(Throwable t) {
			LOG.warn("Cannot return prepared statement and connection", t);
		}
	}
	
}
