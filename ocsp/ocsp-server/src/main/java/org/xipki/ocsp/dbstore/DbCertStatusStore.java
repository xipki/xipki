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

package org.xipki.ocsp.dbstore;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.database.api.DataSource;
import org.xipki.ocsp.CertprofileStore;
import org.xipki.ocsp.IssuerEntry;
import org.xipki.ocsp.IssuerHashNameAndKey;
import org.xipki.ocsp.IssuerStore;
import org.xipki.ocsp.api.CertRevocationInfo;
import org.xipki.ocsp.api.CertStatusInfo;
import org.xipki.ocsp.api.CertStatusStore;
import org.xipki.ocsp.api.CertStatusStoreException;
import org.xipki.ocsp.api.HashAlgoType;

public class DbCertStatusStore implements CertStatusStore
{	
	private static final Logger LOG = LoggerFactory.getLogger(DbCertStatusStore.class);
	
	private final DataSource dataSource;

	private final boolean unknownSerialAsGood;
	private IssuerStore issuerStore;
	private CertprofileStore certprofileStore;
	
	public DbCertStatusStore(DataSource dataSource, boolean unknownSerialAsGood)
	throws SQLException, NoSuchAlgorithmException
	{
		this.dataSource = dataSource;
		this.unknownSerialAsGood = unknownSerialAsGood;
        this.issuerStore = initIssuerStore();
        this.certprofileStore = initCertprofileStore();
	}
	
	private IssuerStore initIssuerStore() 
	throws SQLException
	{
		HashAlgoType[] hashAlgoTypes = {HashAlgoType.SHA1, HashAlgoType.SHA224, HashAlgoType.SHA256,
				HashAlgoType.SHA384, HashAlgoType.SHA512};
		
		StringBuilder sb = new StringBuilder();
		sb.append("SELECT id, subject");
		for(HashAlgoType hashAlgoType : hashAlgoTypes)
		{
			String hashAlgo = hashAlgoType.name().toLowerCase();
			sb.append(", ").append(hashAlgo).append("_fp_name");
			sb.append(", ").append(hashAlgo).append("_fp_key");
		};
		sb.append(" FROM issuer");

		String sql = sb.toString();
        PreparedStatement ps = borrowPreparedStatement(sql);
        
        ResultSet rs = null;
		try{
			rs = ps.executeQuery();
			List<IssuerEntry> caInfos = new LinkedList<IssuerEntry>();
			while(rs.next()) {
				int id = rs.getInt("id");
				String subject = rs.getString("subject");
				
				Map<HashAlgoType, IssuerHashNameAndKey> hashes = new HashMap<HashAlgoType, IssuerHashNameAndKey>();
				for(HashAlgoType hashAlgoType : hashAlgoTypes)
				{
					String hashAlgo = hashAlgoType.name().toLowerCase();
					String hash_name = rs.getString(hashAlgo + "_fp_name");
					String hash_key = rs.getString(hashAlgo + "_fp_key");
					IssuerHashNameAndKey hash = new IssuerHashNameAndKey(
							hashAlgoType, Hex.decode(hash_name), Hex.decode(hash_key));
					hashes.put(hashAlgoType, hash);
				}
				
				IssuerEntry caInfoEntry = new IssuerEntry(id, subject, hashes, null);
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
			Map<Integer, String> entries = new HashMap<Integer, String>();
			
			while(rs.next()) {
				int id = rs.getInt("id");
				String name = rs.getString("name");
				entries.put(id, name);
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
	
	@Override
	public CertStatusInfo getCertStatus(
			HashAlgoType hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash,
			BigInteger serialNumber,
			boolean includeCertHash)
	throws CertStatusStoreException
	{
		try{
			Date thisUpdate = new Date();
			
			IssuerEntry issuer = issuerStore.getIssuerForFp(hashAlgo, issuerNameHash, issuerKeyHash);
			if(issuer == null)
			{
				return CertStatusInfo.getIssuerUnknownCertStatusInfo(thisUpdate, null);
			}
			
			final String sql = 
			    	"id, revocated, rev_reason, rev_time, rev_invalidity_time, certprofile_id" +
			    	" FROM cert" +
			    	" WHERE issuer_id=? AND serial=?";
			
			PreparedStatement ps = borrowPreparedStatement(createFetchFirstSelectSQL(sql, 1));
			ps.setInt(1, issuer.getId());
			ps.setLong(2, serialNumber.longValue());
			ResultSet rs = ps.executeQuery();
			
			try{
				if(rs.next())
				{
					int certprofileId = rs.getInt("certprofile_id");				
					String profileName = certprofileId == 0 ? "NONE" : certprofileStore.getName(certprofileId);
					if(profileName == null)
					{
						// new certprofile has been added after the last update of certprofileStore
						this.certprofileStore = initCertprofileStore();
						profileName = certprofileStore.getName(certprofileId);
					}
					
					byte[] certHash = null;
					if(includeCertHash)
					{
						int certId = rs.getInt("id");
						certHash = getCertHash(certId, hashAlgo);					
					}
					
					CertStatusInfo certStatusInfo;
					boolean revocated = rs.getBoolean("revocated");
					if(revocated)
					{
						int reason = rs.getInt("rev_reason");
						long revocationTime = rs.getLong("rev_time");
						long invalidatityTime = rs.getLong("rev_invalidity_time");
						CertRevocationInfo revInfo = new CertRevocationInfo(reason, new Date(revocationTime * 1000),
								new Date(invalidatityTime * 1000));
						certStatusInfo = CertStatusInfo.getRevocatedCertStatusInfo(revInfo, hashAlgo, certHash,
								thisUpdate, null);
					}
					else
					{
						certStatusInfo = CertStatusInfo.getGoodCertStatusInfo(hashAlgo, certHash, thisUpdate, null);
					}
					
					return certStatusInfo;				
				}
				else
				{
					return unknownSerialAsGood ?
							CertStatusInfo.getGoodCertStatusInfo(hashAlgo, null, thisUpdate, null) :
							CertStatusInfo.getUnknownCertStatusInfo(thisUpdate, null);
				}
			}finally
			{
				rs.close();
			}
		}catch(SQLException e)
		{
			throw new CertStatusStoreException(e);
		}
	}
	
	private byte[] getCertHash(int certId, HashAlgoType hashAlgo)
	throws SQLException
	{
		final String sql = hashAlgo.name().toLowerCase() + "_fp" +
				" FROM certhash WHERE cert_id=?";
		PreparedStatement ps = borrowPreparedStatement(createFetchFirstSelectSQL(sql, 1));
		ps.setInt(1, certId);
		ResultSet rs = ps.executeQuery();
		
		try{
			if(rs.next())
			{
				String hexHash = rs.getString(1);
				return Hex.decode(hexHash);
			}
			else
			{
				return null;
			}
		}finally
		{
			rs.close();
		}
	}
	
	private String createFetchFirstSelectSQL(String coreSql, int rows)
	{
		String prefix = "SELECT";
		String suffix = "";
		
		switch(dataSource.getDatabaseType()) {
			case DB2:
				suffix = "FETCH FIRST " + rows + " ROWS ONLY"; 
				break;
			case INFORMIX:
				prefix = "SELECT FIRST " + rows;
				break;
			case MSSQL2000:
				prefix = "SELECT TOP " + rows;
				break;
			case MYSQL:
				suffix = "LIMIT " + rows;
				break;
			case ORACLE:
				 suffix = "AND ROWNUM <= " + rows;
				break;
			case POSTGRESQL:
				suffix = " FETCH FIRST " + rows + " ROWS ONLY";
				break;
			default:
				break;
		}
		
		return prefix + " " + coreSql + " " + suffix;
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
			LOG.debug("no idle PreparedStatement, create new instance");
			ps = c.prepareStatement(sqlQuery);
		}
		return ps;
	}
	
	private void returnPreparedStatement(PreparedStatement ps)
	{
		try{ 
    		Connection conn = ps.getConnection();
    		dataSource.returnConnection(conn);
    		// TODO ps.closeOnCompletion();
		}catch(Throwable t) {
			LOG.warn("Cannot return prepared statement and connection", t);
		}
	}
}
