/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server.mgmt;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledThreadPoolExecutor;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CAMgmtException;
import org.xipki.ca.api.CAStatus;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.profile.CertProfileException;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.cmp.server.CmpControl;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.ca.server.CmpRequestorInfo;
import org.xipki.ca.server.CrlSigner;
import org.xipki.ca.server.X509CA;
import org.xipki.ca.server.X509CACmpResponder;
import org.xipki.ca.server.store.CertificateStore;
import org.xipki.database.api.DataSource;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.ConfigurationException;
import org.xipki.security.common.DfltEnvironmentParameterResolver;
import org.xipki.security.common.EnvironmentParameterResolver;
import org.xipki.security.common.ParamChecker;

// TODO: add mechanism to lock and unlock the CA to prevent from accessing to the database by more than one CA instance.
public class CAManagerImpl implements CAManager
{
	private static final Logger LOG = LoggerFactory.getLogger(CAManagerImpl.class);
	
	private final CertificateFactory certFact;

	private CertificateStore certstore;
	private DataSource dataSource;
	private CmpResponderEntry responder;

	private final Map<String, CAEntry> cas = new ConcurrentHashMap<String, CAEntry>();
	private final Map<String, CertProfileEntry> certProfiles = new ConcurrentHashMap<String, CertProfileEntry>();
	private final Map<String, PublisherEntry> publishers = new ConcurrentHashMap<String, PublisherEntry>();
	private final Map<String, CmpRequestorEntry> requestors = new ConcurrentHashMap<String, CmpRequestorEntry>();
	private final Map<String, CrlSignerEntry> crlSigners = new ConcurrentHashMap<String, CrlSignerEntry>();
	private final Map<String, Set<String>> ca_has_profiles = new ConcurrentHashMap<String, Set<String>>();
	private final Map<String, Set<String>> ca_has_publishers = new ConcurrentHashMap<String, Set<String>>();
	private final Map<String, Set<CAHasRequestorEntry>> ca_has_requestors = 
			new ConcurrentHashMap<String, Set<CAHasRequestorEntry>>();
	private final Map<String, String> caAliases = new ConcurrentHashMap<String, String>();
	
	private final DfltEnvironmentParameterResolver envParameterResolver = new DfltEnvironmentParameterResolver();
	
	private CmpControl cmpControl;
	
	private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;
	private static final Map<String, X509CACmpResponder> responders =
			new ConcurrentHashMap<String, X509CACmpResponder>();

	private static final Map<String, X509CA> x509cas =
			new ConcurrentHashMap<String, X509CA>();

	private Connection dsConnection;
	
	private PasswordResolver passwordResolver;
	private SecurityFactory securityFactory;
	private DataSourceFactory dataSourceFactory;
	private String caConfFile;

	private boolean caSystemSetuped = false;
	private boolean responderInitialized = false;
	private boolean requestorsInitialized = false;
	private boolean caAliasesInitialized = false;
	private boolean certProfilesInitialized = false;	
	private boolean publishersInitialized = false;
	private boolean crlSignersInitialized = false;
	private boolean cmpControlInitialized = false;
	private boolean cAsInitialized = false;
	private boolean environmentParametersInitialized = false;
	
	public CAManagerImpl() throws ConfigurationException
	{		
		if(Security.getProvider("BC") == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
		
		CertificateFactory cf;
		try {
			cf = CertificateFactory.getInstance("X.509", "BC");
		} catch (CertificateException e) {
			throw new ConfigurationException(e);
		} catch (NoSuchProviderException e) {
			try {
				cf = CertificateFactory.getInstance("X.509");
			} catch (CertificateException e1) {
				throw new ConfigurationException(e);
			}
		}
		
		this.certFact = cf;
	}
	
	private void init() 
	throws CAMgmtException
	{
		if(securityFactory == null)
		{
			throw new IllegalStateException("securityFactory is not set");
		}
		if(dataSourceFactory == null)
		{
			throw new IllegalStateException("dataSourceFactory is not set");
		}
		if(passwordResolver == null)
		{
			throw new IllegalStateException("passwordResolver is not set");
		}
		if(caConfFile == null)
		{
			throw new IllegalStateException("caConfFile is not set");
		}
		
		if(this.dataSource == null)
		{
			try {
				this.dataSource = dataSourceFactory.createDataSourceForFile(caConfFile, passwordResolver);
			} catch (SQLException e) {
				throw new CAMgmtException(e);
			} catch (PasswordResolverException e) {
				throw new CAMgmtException(e);
			} catch (IOException e) {
				throw new CAMgmtException(e);
			}		
			try {
				this.certstore = new CertificateStore(dataSource);
			} catch (SQLException e) {
				throw new CAMgmtException(e);
			}
		}
		
		/*
		Connection conn = getDataSourceConnection();
		Statement stmt = conn.createStatement();
		String sql = "SELECT locked FROM lock";
		ResultSet sqlResult = stmt.executeQuery(sql);		
		
		if(sqlResult.next()){
			boolean locked = sqlResult.getBoolean("locked");
			if(locked)
			{
				throw new Error("The database is locked. Exit the CA");				
			}			
		}
		*/

		initDataObjects();
	}
		
	
	private void reset()
	{
		caSystemSetuped = false;
		responderInitialized = false;
		requestorsInitialized = false;
		caAliasesInitialized = false;
		certProfilesInitialized = false;	
		publishersInitialized = false;
		crlSignersInitialized = false;
		cmpControlInitialized = false;
		cAsInitialized = false;
		environmentParametersInitialized = false;
		
		if(scheduledThreadPoolExecutor != null)
		{
			scheduledThreadPoolExecutor.shutdown();
			scheduledThreadPoolExecutor = null;
		}
	}	
	
	private void initDataObjects() throws CAMgmtException
	{
		initEnvironemtParamters();
		initCaAliases();		
		initCertProfiles();
		initPublishers();		
		initCmpControl();		
		initRequestors();
		initResponder();		
		initCrlSigners();		
		initCAs();
	}

	@Override
	public boolean restartCaSystem()
	{
		reset();
		try{
			initDataObjects();
		}catch(Exception e)
		{
			LOG.error("restartCaSystem().initDataObjects()", e);
			return false;
		}
		
		boolean caSystemStarted = intern_startCaSystem();
		if(caSystemStarted == false)
		{
			LOG.error("Could not start CA system");
		}
		
		return caSystemStarted;
	}
		
	public void startCaSystem()
	{
		boolean caSystemStarted = intern_startCaSystem();
		if(caSystemStarted)
		{
			LOG.info("Started CA system");
		}
		else
		{
			LOG.error("Starting CA system FAILED");
		}
	}
	
	private boolean intern_startCaSystem()
	{
		if(caSystemSetuped)
		{
			return true;
		}
		
		LOG.info("Starting CA system");
		
		try {
			init();
		}catch(Exception e)
		{
			LOG.error("startCaSystem().init()", e);
			return false;
		}
		
		if(scheduledThreadPoolExecutor != null)
		{
			scheduledThreadPoolExecutor.shutdown();
		}
		
		scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(5);
		
		// check the configuration of certificate profiles
		for(CertProfileEntry entry : certProfiles.values())
		{
			try {
				entry.getCertProfile();
			} catch (CertProfileException e) {
				LOG.error("Invalid configuration for the certProfile " + entry.getName()
						+ ",  message: " + e.getMessage());
				return false;
			}
		}

		// check the configuration of certificate publishers
		for(PublisherEntry entry : publishers.values())
		{
			try {
				entry.setPasswordResolver(passwordResolver);
				entry.setDataSourceFactory(dataSourceFactory);
				entry.getCertPublisher();
			} catch (CertPublisherException e) {
				LOG.error("Invalid configuration for the certPublisher " + entry.getName()
						+ ",  message: " + e.getMessage());
				return false;
			}
		}

		responders.clear();
		
		// Add the CAs to the store
		for(String caName : cas.keySet())
		{
			CAEntry caEntry = cas.get(caName);
						
			CrlSigner crlSigner = null;
			if(caEntry.getCrlSignerName() != null)
			{
				CrlSignerEntry crlSignerEntry = crlSigners.get(caEntry.getCrlSignerName());
				String signerType = crlSignerEntry.getType();
				
				ConcurrentContentSigner identifiedSigner = null;
				if("CA".equals(signerType))
				{
				}
				else
				{
					try{
						X509Certificate crlSignerCert = crlSignerEntry.getCertificate();
						identifiedSigner = securityFactory.createSigner(
								signerType, crlSignerEntry.getConf(), crlSignerCert,
								passwordResolver);
						if(crlSignerCert == null)
						{
							crlSignerEntry.setCertificate(identifiedSigner.getCertificate());
						}
					} catch (PasswordResolverException e) {
						LOG.error("security.createSigner crlSigner (ca=" + caName + ")", e);
						return false;
					} catch (SignerException e)
					{
						LOG.error("security.createSigner crlSigner (ca=" + caName + ")", e);
						return false;
					}
					caEntry.getPublicCAInfo().setCrlSignerCertificate(identifiedSigner.getCertificate());
				}
				
				try {
					crlSigner = new CrlSigner(identifiedSigner, crlSignerEntry.getPeriod(), crlSignerEntry.getOverlap());
				} catch (OperationException e) {
					LOG.error("CrlSigner.<init> (ca=" + caName + "): {}", e.getMessage());
					LOG.debug("CrlSigner.<init> (ca=" + caName + ")", e);
					return false;
				}
				crlSigner.setIncludeCertsInCrl(crlSignerEntry.includeCertsInCRL());
			}
			
			ConcurrentContentSigner caSigner;
			try {
				caSigner = securityFactory.createSigner(
						caEntry.getSignerType(), caEntry.getSignerConf(), 
						caEntry.getCertificate().getCert(),
						passwordResolver);
			} catch (PasswordResolverException e) {
				LOG.error("security.createSigner caSigner (ca=" + caName + "): {}", e.getMessage());
				LOG.debug("security.createSigner caSigner (ca=" + caName + ")", e);
				return false;
			} catch (SignerException e)
			{
				LOG.error("security.createSigner caSigner (ca=" + caName + "): {}", e.getMessage());
				LOG.debug("security.createSigner caSigner (ca=" + caName + ")", e);
				return false;
			}
			
			X509CA ca;
			try {
				ca = new X509CA(this, caEntry, caSigner, certstore, crlSigner);
			} catch (OperationException e) {
				LOG.error("X509CA.<init> (ca=" + caName + "): {}", e.getMessage());
				LOG.debug("X509CA.<init> (ca=" + caName + ")", e);
				return false;
			}
			
			x509cas.put(caName, ca);
			
			if(responder != null)
			{
				ConcurrentContentSigner cmpSigner = null;
				try {
					X509Certificate responderCert = responder.getCertificate();
					cmpSigner = securityFactory.createSigner(
							responder.getType(), responder.getConf(), responderCert,
							passwordResolver);
					if(responderCert == null)
					{
						responder.setCertificate(cmpSigner.getCertificate());
					}
				} catch (PasswordResolverException e) {
					LOG.error("X509CA.<init>: {}", e.getMessage());
					LOG.debug("X509CA.<init>", e);
					return false;
				} catch (SignerException e)
				{
					LOG.error("X509CA.<init>: {}", e.getMessage());
					LOG.debug("X509CA.<init>", e);
					return false;
				}		

				X509CACmpResponder caResponder = new X509CACmpResponder(ca, cmpSigner, securityFactory);
				Set<CAHasRequestorEntry> caHasRequestorEntries = getCmpRequestorsForCA(caName);
				if(caHasRequestorEntries != null)
				{
					for(CAHasRequestorEntry entry : caHasRequestorEntries)
					{
						CmpRequestorEntry cmpRequestorEntry = getCmpRequestor(entry.getRequestorName());
						CmpRequestorInfo requestorInfo = new CmpRequestorInfo(
								new X509CertificateWithMetaInfo(cmpRequestorEntry.getCert()),
								entry.isRa());
						requestorInfo.setPermissions(entry.getPermissions());
						requestorInfo.setProfiles(entry.getProfiles());					
						caResponder.addAutorizatedRequestor(requestorInfo);
					}
				}
			
				responders.put(caName, caResponder);
			}
		}
		
		scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(10);
		
		caSystemSetuped = true;
		
		StringBuilder sb = new StringBuilder();

		sb.append("Started CA system");			
    	Set<String> names = new HashSet<String>(getCANames());
    	
    	if(names.size() > 0)
    	{	    		
    		sb.append(" with following CAs: ");
    		Set<String> caAliasNames = getCaAliasNames();	    		
 	    	for(String aliasName : caAliasNames)
	    	{
 	    		String name = getCaName(aliasName);
 	    		names.remove(name);
 	    		
	    		sb.append(name).append(" (alias ").append(aliasName).append(")").append(", ");
	    	}
 	    	
 	    	for(String name : names)
 	    	{
	    		sb.append(name).append(", ");
 	    	}
 	    	
 	    	int len = sb.length();
 	    	sb.delete(len-2, len);
    	}
    	else
    	{
    		sb.append(": no CA is configured");
    	}
    	
		LOG.info("{}", sb);
		
		return true;
	}	
	
	public void shutdown()
	{
		if(scheduledThreadPoolExecutor != null)
		{
			scheduledThreadPoolExecutor.shutdown();
		}
		
		for(String caName : x509cas.keySet())
		{
			X509CA ca = x509cas.get(caName);
			try {
				ca.commitNextSerial();
			} catch (CAMgmtException e) {
				LOG.info("Exception while calling ca.commitNextSerial for ca {}: {}", caName, e.getMessage());
			}
		}
	}

	@Override
	public X509CA getX509CA(String caname)
	{
		return x509cas.get(caname);
	}
	
	@Override
	public X509CACmpResponder getX509CACmpResponder(String caname)
	{
		return responders.get(caname);
	}
	
	public ScheduledThreadPoolExecutor getScheduledThreadPoolExecutor() {
		return scheduledThreadPoolExecutor;
	}

	@Override
	public Set<String> getCertProfileNames()
	{
		return certProfiles.keySet();
	}

	@Override
	public Set<String> getPublisherNames()
	{
		return publishers.keySet();
	}

	@Override
	public Set<String> getCmpRequestorNames()
	{
		return requestors.keySet();
	}

	@Override
	public Set<String> getCrlSignerNames()
	{
		return crlSigners.keySet();
	}
	
	@Override
	public Set<String> getCANames()
	{
		return cas.keySet();
	}
	
	private void initRequestors()
			throws CAMgmtException 
	{
		if(requestorsInitialized) return;
		
		requestors.clear();
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			ResultSet rs = stmt.executeQuery(
					"SELECT name, cert FROM requestor");
			
			try{
				while(rs.next())
				{
					String name = rs.getString("name");
					String b64Cert = rs.getString("cert");
					X509Certificate cert = generateCert(b64Cert);
					CmpRequestorEntry entry = new CmpRequestorEntry(name);
					entry.setCert(cert);
					requestors.put(entry.getName(), entry);
				}
			}finally
			{
				rs.close();
				rs = null;
			}
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(stmt);
		}
		
		requestorsInitialized = true;
	}
	
	private void initResponder() throws CAMgmtException
	{
		if(responderInitialized) return;
		
		this.responder = null;
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			ResultSet sqlResult = stmt.executeQuery("SELECT type, conf, cert FROM responder");
			
			while(sqlResult.next())
			{
				if(this.responder != null)
				{
					throw new CAMgmtException("More than one CMPResponder is configured, but maximal one is allowed");
				}
				
				CmpResponderEntry entry = new CmpResponderEntry();
				
				String type = sqlResult.getString("type");
				entry.setType(type);

				String conf = sqlResult.getString("conf");
				entry.setConf(conf);

				String b64Cert = sqlResult.getString("cert");
				if(b64Cert != null)
				{
					X509Certificate cert = generateCert(b64Cert);
					entry.setCertificate(cert);
				}
				
				this.responder = entry;
			}
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(stmt);
		}
		
		responderInitialized = true;
	}
	
	private X509Certificate generateCert(String b64Cert) throws CAMgmtException
	{
		if(b64Cert == null)
		{
			return null;
		}
		
		byte[] encodedCert = Base64.decode(b64Cert);
		try {
			return (X509Certificate) certFact.generateCertificate(new ByteArrayInputStream(encodedCert));
		} catch (CertificateException e) {
			throw new CAMgmtException(e);
		}
	}	
	
	private void initEnvironemtParamters() throws CAMgmtException
	{
		if(environmentParametersInitialized) return;
		
		envParameterResolver.clear();
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			String sql = "SELECT name, value FROM environment";
			ResultSet rs = stmt.executeQuery(sql);		
			
			while(rs.next()){
				String name = rs.getString("name");
				String value = rs.getString("value");
				
				envParameterResolver.addEnvParam(name, value);
			}
			
			rs.close();
			rs = null;
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(stmt);
		}
		
		environmentParametersInitialized = true;
	}

	private void initCaAliases() throws CAMgmtException
	{
		if(caAliasesInitialized) return;
		
		caAliases.clear();
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			String sql = "SELECT name, ca_name FROM caalias";
			ResultSet rs = stmt.executeQuery(sql);		
			
			while(rs.next()){
				String name = rs.getString("name");
				String caName = rs.getString("ca_name");
				
				caAliases.put(name, caName);
			}
			
			rs.close();
			rs = null;
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(stmt);
		}
		
		caAliasesInitialized = true;
	}

	private void initCertProfiles() throws CAMgmtException
	{
		if(certProfilesInitialized) return;
		
		certProfiles.clear();
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			String sql = "SELECT name, type, conf FROM certprofile";
			ResultSet rs = stmt.executeQuery(sql);		
			
			while(rs.next()){
				String name = rs.getString("name");
				String type = rs.getString("type");
				String conf = rs.getString("conf");
				
				CertProfileEntry entry = new CertProfileEntry(name);
				entry.setEnvironmentParamterResolver(envParameterResolver);
				entry.setType(type);
				entry.setConf(conf);
				certProfiles.put(entry.getName(), entry);
			}
			
			rs.close();
			rs = null;
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		} finally
		{
			closeStatement(stmt);
		}
		
		certProfilesInitialized = true;
	}

	private void initPublishers() throws CAMgmtException
	{
		if(publishersInitialized) return;
		
		publishers.clear();
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			String sql = "SELECT name, type, conf FROM publisher";
			ResultSet rs = stmt.executeQuery(sql);		
			
			while(rs.next()){
				String name = rs.getString("name");
				String type = rs.getString("type");
				String conf = rs.getString("conf");
				
				PublisherEntry entry = new PublisherEntry(name);
				entry.setType(type);
				entry.setConf(conf);
				entry.setPasswordResolver(passwordResolver);
				entry.setDataSourceFactory(dataSourceFactory);
				entry.setEnvironmentParamterResolver(envParameterResolver);
				publishers.put(entry.getName(), entry);
			}
			
			rs.close();
			rs = null;
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(stmt);
		}
		
		publishersInitialized = true;
	}

	private void initCrlSigners() throws CAMgmtException
	{
		if(crlSignersInitialized) return;

		crlSigners.clear();
		
		Statement stmt = null;
		try{
			stmt = createStatement();

			String sql = "SELECT name, signer_type, signer_conf, signer_cert, period,"
					+ " overlap, include_certs_in_crl"
					+ " FROM crlsigner";
			ResultSet rs = stmt.executeQuery(sql);		
			
			while(rs.next()){
				String name = rs.getString("name");
				String signer_type = rs.getString("signer_type");
				String signer_conf = rs.getString("signer_conf");
				String signer_cert = rs.getString("signer_cert");
				int period = rs.getInt("period");
				int overlap = rs.getInt("overlap");
				boolean include_certs_in_crl = rs.getBoolean("include_certs_in_crl");
				
				CrlSignerEntry entry = new CrlSignerEntry(name);
				entry.setType(signer_type);
				if(!"CA".equalsIgnoreCase(signer_type))
				{
					entry.setConf(signer_conf);
					if(signer_cert != null)
					{
						entry.setCertificate(generateCert(signer_cert));
					}
				}			
				entry.setPeriod(period);
				entry.setOverlap(overlap);
				entry.setIncludeCertsInCrl(include_certs_in_crl);
				crlSigners.put(entry.getName(), entry);
			}
			
			rs.close();
			rs = null;
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		} catch (ConfigurationException e) {
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(stmt);
		}
		
		crlSignersInitialized = true;
	}
	
	

	private void initCmpControl() throws CAMgmtException
	{
		if(cmpControlInitialized) return;

		cmpControl = null;
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			String sql = "SELECT require_confirm_cert, send_ca_cert, "
					+ " message_time_bias, confirm_wait_time"
					+ " FROM cmpcontrol";
	
			ResultSet rs = stmt.executeQuery(sql);		
			
			if(rs.next()){
				boolean requireConfirmCert = rs.getBoolean("require_confirm_cert");
				boolean sendCaCert = rs.getBoolean("send_ca_cert");
				int messageTimeBias = rs.getInt("message_time_bias");
				int confirmWaitTime = rs.getInt("confirm_wait_time");
				
				CmpControl entry = new CmpControl();
				entry.setRequireConfirmCert(requireConfirmCert);
				entry.setSendCaCert(sendCaCert);
				
				if(messageTimeBias != 0)
				{
					entry.setMessageBias(messageTimeBias);
				}
				if(confirmWaitTime != 0)
				{
					entry.setConfirmWaitTime(confirmWaitTime);
				}
	
				cmpControl = entry;
			}
			
			rs.close();
			rs = null;
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(stmt);
		}
		
		cmpControlInitialized = true;
	}
	

	private void initCAs() throws CAMgmtException	
	{
		if(cAsInitialized) return;
		
		cas.clear();
		ca_has_requestors.clear();
		ca_has_publishers.clear();
		ca_has_profiles.clear();
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			
			ResultSet rs = stmt.executeQuery(
					"SELECT name, next_serial, status, crl_uris, ocsp_uris, max_validity, "
					+ "cert, signer_type, signer_conf, crlsigner_name, "
					+ "allow_duplicate_key, allow_duplicate_subject, permissions, num_crls FROM ca");
	
			while(rs.next())
			{
				String name = rs.getString("name");
				long next_serial = rs.getLong("next_serial");
				String status = rs.getString("status");
				String crl_uris = rs.getString("crl_uris");
				String ocsp_uris = rs.getString("ocsp_uris");			
				int max_validity = rs.getInt("max_validity");
				String b64cert = rs.getString("cert");
				String signer_type = rs.getString("signer_type");
				String signer_conf = rs.getString("signer_conf");
				String crlsigner_name = rs.getString("crlsigner_name");
				boolean allowDuplicateKey = rs.getBoolean("allow_duplicate_key");
				boolean allowDuplicateSubject = rs.getBoolean("allow_duplicate_subject");
				int numCrls = rs.getInt("num_crls");
				
				String s = rs.getString("permissions");
				Set<Permission> permissions = getPermissions(s);
	
				List<String> lCrlUris = null;
				if(crl_uris != null && !crl_uris.isEmpty())
				{
					lCrlUris = tokensAsList(crl_uris, " \t");
				}
				
				List<String> lOcspUris = null;
				if(ocsp_uris != null && !ocsp_uris.isEmpty())
				{
					lOcspUris = tokensAsList(ocsp_uris, " \t");
				}			
	
				X509Certificate cert = generateCert(b64cert);
	
				CAEntry entry = new CAEntry(name, next_serial, signer_type, signer_conf, cert,
						lOcspUris, lCrlUris, null, numCrls);				
				entry.setLastCommittedNextSerial(next_serial);
	
				CAStatus caStatus = CAStatus.getCAStatus(status);
				if(caStatus == null)
				{
					caStatus = CAStatus.INACTIVE;
				}			
				entry.setStatus(caStatus);
				
				entry.setMaxValidity(max_validity);
				
				if(crlsigner_name != null)
				{
					entry.setCrlSignerName(crlsigner_name);
				}
				
				entry.setAllowDuplicateKey(allowDuplicateKey);
				entry.setAllowDuplicateSubject(allowDuplicateSubject);
				entry.setPermissions(permissions);
				
				cas.put(entry.getName(), entry);
			}
			
			rs.close();
			
			rs = stmt.executeQuery("SELECT ca_name, requestor_name, ra, permissions, profiles FROM ca_has_requestor");
			while(rs.next())
			{
				String ca_name = rs.getString("ca_name");
				String requestor_name = rs.getString("requestor_name");
				boolean ra = rs.getBoolean("ra");
				String s = rs.getString("permissions");
				Set<Permission> permissions = getPermissions(s);
	
				s = rs.getString("profiles");			
				List<String> list = tokensAsList(s, ",");
				Set<String> profiles = (list == null)? null : new HashSet<String>(list);
				
				Set<CAHasRequestorEntry> requestors = ca_has_requestors.get(ca_name);
				if(requestors == null)
				{
					requestors = new HashSet<CAHasRequestorEntry>();
					ca_has_requestors.put(ca_name, requestors);
				}
				
				CAHasRequestorEntry entry = new CAHasRequestorEntry(requestor_name);
				entry.setRa(ra);
				entry.setPermissions(permissions);
				entry.setProfiles(profiles);
				requestors.add(entry);
			}
			rs.close();
			
			rs = stmt.executeQuery("SELECT ca_name, certprofile_name FROM ca_has_certprofile");
			while(rs.next())
			{
				String ca_name = rs.getString("ca_name");
				String certprofile_name = rs.getString("certprofile_name");
				Set<String> certprofile_names = ca_has_profiles.get(ca_name);
				if(certprofile_names == null)
				{
					certprofile_names = new HashSet<String>();
					ca_has_profiles.put(ca_name, certprofile_names);
				}
				certprofile_names.add(certprofile_name);
			}
			rs.close();
			
			rs = stmt.executeQuery(
					"SELECT ca_name, publisher_name FROM ca_has_publisher");
			while(rs.next())
			{
				String ca_name = rs.getString("ca_name");
				String publisher_name = rs.getString("publisher_name");
				Set<String> publisher_names = ca_has_publishers.get(ca_name);
				if(publisher_names == null)
				{
					publisher_names = new HashSet<String>();
					ca_has_publishers.put(ca_name, publisher_names);
				}
				publisher_names.add(publisher_name);
			}
			
			rs.close();
			rs = null;
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(stmt);
		}
		
		cAsInitialized = true;
	}

	@Override
	public void addCA(CAEntry newCaDbEntry) throws CAMgmtException
	{
		String name = newCaDbEntry.getName();
		
		if(cas.containsKey(name))
		{
			throw new CAMgmtException("CA named " + name + " exists");
		}
		
		// insert to table ca
		PreparedStatement ps = null;
		try{
			ps = prepareStatement(
					"INSERT INTO ca (name, subject, next_serial, status, crl_uris, ocsp_uris, max_validity, "
					+ "cert, signer_type, signer_conf, crlsigner_name, "
					+ "allow_duplicate_key, allow_duplicate_subject, permissions, num_crls) "
					+ "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			int idx = 1;
			ps.setString(idx++, name);
			ps.setString(idx++, newCaDbEntry.getSubject());
			ps.setLong(idx++, newCaDbEntry.getNextSerial());
			ps.setString(idx++, newCaDbEntry.getStatus().getStatus());
			ps.setString(idx++, newCaDbEntry.getCrlUrisAsString());
			ps.setString(idx++, newCaDbEntry.getOcspUrisAsString());
			ps.setInt(idx++, newCaDbEntry.getMaxValidity());
			ps.setString(idx++, Base64.toBase64String(newCaDbEntry.getCertificate().getEncodedCert()));
			ps.setString(idx++, newCaDbEntry.getSignerType());
			ps.setString(idx++, newCaDbEntry.getSignerConf());
			ps.setString(idx++, newCaDbEntry.getCrlSignerName());
			ps.setBoolean(idx++, newCaDbEntry.isAllowDuplicateKey());
			ps.setBoolean(idx++, newCaDbEntry.isAllowDuplicateSubject());
			ps.setString(idx++, toString(newCaDbEntry.getPermissions()));
			ps.setInt(idx++, newCaDbEntry.getNumCrls());
			
			ps.executeUpdate();	
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
		
		cas.put(newCaDbEntry.getName(), newCaDbEntry);
	}	
	
	@Override
	public CAEntry getCA(String caName)
	{
		return cas.get(caName);
	}
	
	@Override
	public void changeCA(String name, CAStatus status, Long nextSerial,
			X509Certificate cert,
			Set<String> crl_uris, Set<String> ocsp_uris,
			Integer max_validity, String signer_type, String signer_conf,
			String crlsigner_name, Boolean allow_duplicate_key, 
			Boolean allow_duplicate_subject, Set<Permission> permissions,
			Integer numCrls)
	throws CAMgmtException
	{
		if(cas.containsKey(name) == false)
		{
			throw new CAMgmtException("Could not find CA named " + name);
		}
		
		if(nextSerial != null)
		{
			CAEntry caEntry = cas.get(name);
			if(caEntry.getNextSerial() > nextSerial + 1) // 1 as buffer
			{
				throw new CAMgmtException("the nextSerial " + nextSerial + " is not allowed");
			}
		}		
		
		StringBuilder sb = new StringBuilder();
		sb.append("UPDATE ca SET ");
		
		int i = 1;
		
		Integer iStatus = null;
		if(status != null)
		{
			sb.append("status=?,");
			iStatus = i++;
		}
		
		Integer iNext_serial = null;
		if(nextSerial != null)
		{
			sb.append("next_serial=?,");
			iNext_serial = i++;
		}		
		
		Integer iSubject = null;
		Integer iCert = null;
		if(cert != null)
		{
			sb.append("subject=?,");
			iSubject = i++;
			
			sb.append("cert=?,");
			iCert = i++;
		}
		
		Integer iCrl_uris = null;
		if(crl_uris != null)
		{
			sb.append("crl_uris=?,");
			iCrl_uris = i++;
		}
		
		Integer iOcsp_uris = null;
		if(ocsp_uris != null)
		{
			sb.append("ocsp_uris=?,");
			iOcsp_uris = i++;
		}
		
		Integer iMax_validity = null;
		if(max_validity != null)
		{
			sb.append("max_validity=?,");
			iMax_validity = i++;
		}
		
		Integer iSigner_type = null;
		if(signer_type != null)
		{
			sb.append("signer_type=?,");
			iSigner_type = i++;
		}
		
		Integer iSigner_conf = null;
		if(signer_conf != null)
		{
			sb.append("signer_conf=?,");
			iSigner_conf = i++;
		}
		
		Integer iCrlsigner_name = null;
		if(crlsigner_name != null)
		{
			sb.append("crlsigner_name=?,");
			iCrlsigner_name = i++;
		}

		Integer iAllow_duplicate_key = null;
		if(allow_duplicate_key != null)
		{
			sb.append("allow_duplicate_key=?,");
			iAllow_duplicate_key = i++;
		}
		
		Integer iAllow_duplicate_subject = null;
		if(allow_duplicate_subject != null)
		{
			sb.append("allow_duplicate_subject=?,");
			iAllow_duplicate_subject = i++;
		}
		
		Integer iPermissions = null;
		if(permissions != null)
		{
			sb.append("permissions=?,");
			iPermissions = i++;
		}		
		
		Integer iNum_crls = null;
		if(numCrls != null)
		{
			sb.append("num_crls=?,");
			iNum_crls = i++;
		}		

		// delete the last ','
		sb.deleteCharAt(sb.length() - 1);
		sb.append(" WHERE name=?");
		
		if(i == 1)
		{
			return;
		}
		int iName = i;
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement(sb.toString());
			
			if(iStatus != null)
			{
				ps.setString(iStatus, status.name());
			}
	
			if(iNext_serial != null)
			{
				ps.setLong(iNext_serial, nextSerial.longValue());
			}
			
			if(iCert != null)
			{
				ps.setString(iSubject, cert.getSubjectX500Principal().getName());
				
				String base64Cert = Base64.toBase64String(cert.getEncoded());
				ps.setString(iCert, base64Cert);
			}
			
			if(iCrl_uris != null)
			{			
				ps.setString(iCrl_uris, toString(crl_uris, ","));
			}
	
			if(iOcsp_uris != null)
			{
				ps.setString(iOcsp_uris, toString(ocsp_uris, ","));
			}
			
			if(iMax_validity != null)
			{
				ps.setInt(iMax_validity, max_validity);
			}
	
			if(iSigner_type != null)
			{
				ps.setString(iSigner_type, signer_type);
			}
	
			if(iSigner_conf != null)
			{
				ps.setString(iSigner_conf, signer_conf);
			}
	
			if(iCrlsigner_name != null)
			{
				ps.setString(iCrlsigner_name, getRealString(crlsigner_name));
			}
	
			if(iAllow_duplicate_key != null)
			{
				ps.setBoolean(iAllow_duplicate_key, allow_duplicate_key);
			}
	
			if(iAllow_duplicate_subject != null)
			{
				ps.setBoolean(iAllow_duplicate_subject, allow_duplicate_subject);
			}
	
			if(iPermissions != null)
			{
				ps.setString(iPermissions, toString(permissions));
			}
	
			if(iNum_crls != null)
			{
				ps.setInt(iNum_crls, numCrls);
			}
			
			ps.setString(iName, name);
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		} catch (CertificateEncodingException e) {
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
		
	}
	
	@Override
	public void setCANextSerial(String caName, long nextSerial) throws CAMgmtException
	{
		CAEntry caInfo = cas.get(caName);
		if(caInfo == null)
		{
			throw new CAMgmtException("Could not find CA named " + caName);
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("UPDATE ca SET next_serial=? WHERE name=?");
			ps.setLong(1, nextSerial);
			ps.setString(2, caName);
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
	}

	@Override
	public void removeCertProfileFromCA(String profileName, String caName)
	throws CAMgmtException
	{
		Set<String> profileNames = ca_has_profiles.get(caName);
		if(profileNames == null)
		{
			return;
		}
		
		if(profileNames.contains(profileName))
		{
			return;
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("DELETE FROM ca_has_certprofile WHERE ca_name=? AND certprofile_name=?");
			ps.setString(1, caName);
			ps.setString(2, profileName);
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
		
		profileNames.remove(profileName);
	}

	@Override
	public void addCertProfileToCA(String profileName, String caName)
	throws CAMgmtException
	{
		Set<String> profileNames = ca_has_profiles.get(caName);
		if(profileNames == null)
		{
			profileNames = new HashSet<String>();
			ca_has_profiles.put(caName, profileNames);
		}
		else
		{
			if(profileNames.contains(profileName))
			{
				return;
			}
		}
		profileNames.add(profileName);

		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO ca_has_certprofile (ca_name, certprofile_name) VALUES (?, ?)");
			ps.setString(1, caName);
			ps.setString(2, profileName);
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
	}

	@Override
	public void removePublisherFromCA(String publisherName, String caName)
	throws CAMgmtException
	{
		Set<String> publisherNames = ca_has_publishers.get(caName);
		if(publisherNames == null)
		{
			return;
		}
		
		if(publisherNames.contains(publisherName) == false)
		{
			return;
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("DELETE FROM ca_has_publisher WHERE ca_name=? AND publisher_name=?");
			ps.setString(1, caName);
			ps.setString(2, publisherName);
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
		
		publisherNames.remove(publisherName);
	}

	@Override
	public void addPublisherToCA(String publisherName, String caName)
	throws CAMgmtException
	{
		Set<String> publisherNames = ca_has_publishers.get(caName);
		if(publisherNames == null)
		{
			publisherNames = new HashSet<String>();
			ca_has_publishers.put(caName, publisherNames);
		}
		else
		{
			if(publisherNames.contains(publisherName))
			{
				return;
			}
		}
		publisherNames.add(publisherName);

		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO ca_has_publisher (ca_name, publisher_name) VALUES (?, ?)");
			ps.setString(1, caName);
			ps.setString(2, publisherName);
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
	}

	private static void closeStatement(Statement ps)
	{
		if(ps != null)
		{
			try {
				ps.close();
			} catch (SQLException e) {
			}
		}
	}

	@Override
	public Set<String> getCertProfilesForCA(String caName)
	{
		return ca_has_profiles.get(caName);
	}

	@Override
	public Set<CAHasRequestorEntry> getCmpRequestorsForCA(String caName)
	{
		return ca_has_requestors.get(caName);
	}

	@Override
	public CmpRequestorEntry getCmpRequestor(String name)
	{
		return requestors.get(name);
	}
	
	@Override
	public void addCmpRequestor(CmpRequestorEntry dbEntry)
	throws CAMgmtException
	{
		String name = dbEntry.getName();
		if(requestors.containsKey(name))
		{
			throw new CAMgmtException("CMP requestor named " + name + " exists");
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO requestor (name, cert) VALUES (?, ?)");
			int idx = 1;
			ps.setString(idx++, name);
			ps.setString(idx++, Base64.toBase64String(dbEntry.getCert().getEncoded()));
			
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		} catch (CertificateEncodingException e) {
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
		
		requestors.put(name, dbEntry);
	}
	
	@Override
	public void removeCmpRequestor(String requestorName)
	throws CAMgmtException
	{
		if(requestors.containsKey(requestorName) == false)
		{
			return;
		}

		for(String caName : ca_has_requestors.keySet()){
			removeCmpRequestorFromCA(requestorName, caName);
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("DELETE FROM requestor WHERE name=?");
			ps.setString(1, requestorName);
			int rows = ps.executeUpdate();
			if(rows != 1)
			{
				throw new CAMgmtException("Could not remove cmpRequestor " + requestorName);
			}
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
		
		requestors.remove(requestorName);
	}
	
	@Override
	public void changeCmpRequestor(String name, String cert)
	throws CAMgmtException
	{
		if(cert == null)
		{
			return;
		}

		if(requestors.containsKey(name) == false)
		{
			throw new CAMgmtException("Could not find requestor " + name);
		}
		
		String sql = "UPDATE requestor SET cert=? WHERE name=?";
		PreparedStatement ps = null;
		try{
			ps = prepareStatement(sql);
			ps.setString(1, getRealString(cert));
			ps.setString(2, name);		
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
	}
	
	@Override
	public void removeCmpRequestorFromCA(String requestorName, String caName)
	throws CAMgmtException
	{
		Set<CAHasRequestorEntry> requestors = ca_has_requestors.get(caName);
		if(requestors == null)
		{
			return;
		}

		boolean foundEntry = false;
		for(CAHasRequestorEntry entry : requestors)
		{
			if(entry.getRequestorName().equals(requestorName))
			{
				foundEntry = true;
				break;
			}
		}
		if(! foundEntry)
		{
			return;
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("DELETE FROM ca_has_requestor WHERE ca_name=? AND requestor_name=?");
			ps.setString(1, caName);
			ps.setString(2, requestorName);
			ps.executeUpdate();
			
			requestors.remove(requestorName);
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
	}

	@Override
	public void addCmpRequestorToCA(CAHasRequestorEntry requestor, String caName)
	throws CAMgmtException
	{
		String requestorName = requestor.getRequestorName();
		Set<CAHasRequestorEntry> cmpRequestors = ca_has_requestors.get(caName);
		if(cmpRequestors == null)
		{
			cmpRequestors = new HashSet<CAHasRequestorEntry>();
			ca_has_requestors.put(caName, cmpRequestors);
		}
		else
		{
			boolean foundEntry = false;
			for(CAHasRequestorEntry entry : cmpRequestors)
			{
				if(entry.getRequestorName().equals(requestorName))
				{
					foundEntry = true;
					break;
				}
			}
			
			// already added
			if(foundEntry)
			{
				throw new CAMgmtException("ca_has_requestor with caname=" + caName + 
						" and requestor_name="+ requestorName + " exists");
			}
		}
		
		cmpRequestors.add(requestor);

		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO ca_has_requestor "
					+ "(ca_name, requestor_name, ra, permissions, profiles) VALUES (?, ?, ?, ?, ?)");
			int idx = 1;
			ps.setString(idx++, caName);
			ps.setString(idx++, requestorName);
			ps.setBoolean(idx++, requestor.isRa());
			ps.setString(idx++, toString(requestor.getPermissions()));
	
			Set<String> profiles = requestor.getProfiles();
			ps.setString(idx++, toString(profiles, ","));
	
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}

	}
	
	@Override
	public CertProfileEntry getCertProfile(String profileName)
	{
		return certProfiles.get(profileName);
	}

	@Override
	public void removeCertProfile(String profileName)
	throws CAMgmtException
	{
		if(certProfiles.containsKey(profileName) == false)
		{
			return;
		}

		for(String caName : ca_has_profiles.keySet()){
			removeCertProfileFromCA(profileName, caName);
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("DELETE FROM certprofile WHERE name=?");
			ps.setString(1, profileName);
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}

		certProfiles.remove(profileName);
	}

	@Override
	public void changeCertProfile(String name, String type, String conf)
	throws CAMgmtException
	{
		if(type == null && conf == null)
		{
			throw new IllegalArgumentException("at least one of type and conf should not be null");
		}
		assertNotNULL("type", type);

		if(certProfiles.containsKey(name))
		{
			throw new CAMgmtException("Could not find certificate profile " + name);
		}
		
		StringBuilder sb = new StringBuilder();		
		sb.append("UPDATE environment SET ");
		
		Integer iType = null;
		Integer iConf = null;
		
		int i = 1;
		if(type != null)
		{
			sb.append("type=?,");
			iType = i++;
		}
		if(conf != null)
		{
			sb.append("conf=?,");
			iConf = i++;
		}
		
		sb.deleteCharAt(sb.length() - 1);
		sb.append(" WHERE name=?");
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement(sb.toString());
			if(iType != null)
			{
				ps.setString(iType, type);
			}
			
			if(iConf != null)
			{
				ps.setString(iConf, getRealString(conf));
			}

			ps.setString(i, name);
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
	}
	
	@Override
	public void addCertProfile(CertProfileEntry dbEntry) throws CAMgmtException
	{
		String name = dbEntry.getName();
		if(certProfiles.containsKey(name))
		{
			throw new CAMgmtException("CertProfile named " + name + " exists");
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO certprofile (name, type, conf) VALUES (?, ?, ?)");
			ps.setString(1, name);
			ps.setString(2, dbEntry.getType());
			String conf = dbEntry.getConf();
			ps.setString(3, conf);
			
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}

		dbEntry.setEnvironmentParamterResolver(envParameterResolver);
		certProfiles.put(name, dbEntry);
	}

	@Override
	public void setCmpResponder(CmpResponderEntry dbEntry)
	throws CAMgmtException
	{
		if(responder != null)
		{
			removeCmpResponder();
		}
		
		responder = dbEntry;
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO responder (name, type, conf, cert) VALUES (?, ?, ?, ?)");
			int idx = 1;
			ps.setString(idx++, CmpResponderEntry.name);
			ps.setString(idx++, dbEntry.getType());
			ps.setString(idx++, dbEntry.getConf());
			
			String b64Cert = null;
			X509Certificate cert = dbEntry.getCertificate();
			if(cert != null)
			{
				b64Cert = Base64.toBase64String(dbEntry.getCertificate().getEncoded());
			}
			ps.setString(idx++, b64Cert);
			
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		} catch (CertificateEncodingException e) {
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
	}
	
	@Override
	public void removeCmpResponder()
	throws CAMgmtException
	{
		if(responder == null)		
		{
			return;
		}

		Statement stmt = null;
		try {
			stmt = createStatement();
			stmt.execute("DELETE FROM responder");
		} catch (SQLException e) {
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(stmt);
		}

		responder = null;		
	}
	
	@Override
	public void changeCmpResponder(String type, String conf, String cert)
	throws CAMgmtException
	{
		if(type == null && conf == null && cert == null)
		{
			return;
		}

		if(responder == null)
		{
			throw new CAMgmtException("No CMP responder is configured");
		}
		
		StringBuilder sb = new StringBuilder();		
		sb.append("UPDATE responder SET ");
		
		Integer iType = null;
		Integer iConf = null;
		Integer iCert = null;
		
		int i = 1;
		if(type != null)
		{
			sb.append("type=?,");
			iType = i++;
		}
		if(conf != null)
		{
			sb.append("conf=?,");
			iConf = i++;
		}
		if(cert != null)
		{
			sb.append("cert=?,");
			iCert = i++;
		}
		
		sb.deleteCharAt(sb.length() - 1);
		sb.append(" WHERE name=?");
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement(sb.toString());
			if(iType != null)
			{
				ps.setString(iType, getRealString(type));
			}
		
			if(iConf != null)
			{
				ps.setString(iConf, getRealString(conf));
			}
			
			if(iCert != null)
			{
				ps.setString(iCert, getRealString(cert));
			}
			ps.setString(i, CmpResponderEntry.name);
			
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
	}
	
	@Override
	public CmpResponderEntry getCmpResponder()
	{
		return responder;
	}
	
	@Override
	public void addCrlSigner(CrlSignerEntry dbEntry)
	throws CAMgmtException
	{
		String name = dbEntry.getName();
		if(crlSigners.containsKey(name))
		{
			throw new CAMgmtException("CRL signer named " + name + " exists");
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement(
					"INSERT INTO crlsigner (name, signer_type, signer_conf, signer_cert, period, overlap, include_certs_in_crl)"
					+ " VALUES (?, ?, ?, ?, ?, ?, ?)");
			int idx = 1;
			ps.setString(idx++, name);
			ps.setString(idx++, dbEntry.getType());
			ps.setString(idx++, dbEntry.getConf());
			ps.setString(idx++, dbEntry.getCertificate() == null ? null : 
					Base64.toBase64String(dbEntry.getCertificate().getEncoded()));
			ps.setInt(idx++, dbEntry.getPeriod());
			ps.setInt(idx++, dbEntry.getOverlap());
			ps.setBoolean(idx++, dbEntry.includeCertsInCRL());
			
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		} catch (CertificateEncodingException e) {
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
		
		crlSigners.put(name, dbEntry);
	}
	
	@Override
	public void removeCrlSigner(String crlSignerName)
	throws CAMgmtException
	{
		if(crlSigners.containsKey(crlSignerName) == false)
		{
			return;
		}

		for(String caName : cas.keySet()){
			CAEntry caInfo = cas.get(caName);
			if(crlSignerName.equals(caInfo.getCrlSignerName()))
			{
				setCrlSignerInCA(null, caName);
			}
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("DELETE FROM crlsigner WHERE name=?");
			ps.setString(1, crlSignerName);
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
		
		crlSigners.remove(crlSignerName);
	}
	
	@Override
	public void changeCrlSigner(String name, String signer_type, String signer_conf, String signer_cert, 
			Integer period, Integer overlap, Boolean includeCerts)
	throws CAMgmtException
	{
		if(crlSigners.containsKey(name) == false)
		{
			throw new CAMgmtException("Unknown CRL signer " + name);
		}
		
		StringBuilder sb = new StringBuilder();		
		sb.append("UPDATE crlsigner SET ");
		
		int i = 1;

		Integer iSigner_type = null;		
		if(signer_type != null)
		{
			sb.append("signer_type=?,");
			iSigner_type = i++;
		}

		Integer iSigner_conf = null;
		if(signer_conf != null)
		{
			sb.append("signer_conf=?,");
			iSigner_conf = i++;
		}		
		
		Integer iSigner_cert = null;
		if(signer_cert != null)
		{
			sb.append("signer_cert=?,");
			iSigner_cert = i++;
		}
		
		Integer iPeriod = null;
		if(period != null)
		{
			sb.append("period=?,");
			iPeriod = i++;
		}		
		
		Integer iOverlap = null;
		if(overlap != null)
		{
			sb.append("overlap=?,");
			iOverlap = i++;
		}		
		
		Integer iIncludeCerts = null;
		if(includeCerts != null)
		{
			sb.append("include_certs_in_crl=?,");
			iIncludeCerts = i++;
		}		
		
		sb.deleteCharAt(sb.length() - 1);
		sb.append(" WHERE name=?");
		
		if(i == 1)
		{
			return;
		}
		int iName = i;
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement(sb.toString());
			
			if(iSigner_type != null)
			{
				ps.setString(iSigner_type, signer_type);
			}
			
			if(iSigner_conf != null)
			{
				ps.setString(iSigner_conf, getRealString(signer_conf));
			}
	
			if(iSigner_cert != null)
			{
				ps.setString(iSigner_cert, getRealString(signer_cert));
			}
	
			if(iPeriod != null)
			{
				ps.setInt(iPeriod, period);
			}
	
			if(iOverlap != null)
			{
				ps.setInt(iPeriod, overlap);
			}
	
			if(iIncludeCerts != null)
			{
				ps.setBoolean(iIncludeCerts, includeCerts);
			}
	
			ps.setString(iName, name);
			
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
	}
	
	@Override
	public CrlSignerEntry getCrlSigner(String name)
	{
		return crlSigners.get(name);
	}

	@Override
	public void setCrlSignerInCA(String crlSignerName, String caName)
	throws CAMgmtException
	{
		CAEntry caInfo = cas.get(caName);
		if(caInfo == null)
		{
			throw new CAMgmtException("Unknown CA " + caName);
		}
		
		String oldCrlSignerName = caInfo.getCrlSignerName();
		if(oldCrlSignerName == crlSignerName)
		{
			return;
		}
		
		if(crlSignerName != null && !crlSigners.containsKey(crlSignerName))
		{
			throw new CAMgmtException("Unknown CRL signer " + crlSignerName);
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("UPDATE ca SET crlsigner_name=? WHERE name=?");
			ps.setString(1, crlSignerName);
			ps.setString(2, caName);
			
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
	}
	
	@Override
	public void addPublisher(PublisherEntry dbEntry) throws CAMgmtException
	{
		String name = dbEntry.getName();
		if(publishers.containsKey(name))
		{
			throw new CAMgmtException("Publisher named " + name + " exists");
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO publisher (name, type, conf) VALUES (?, ?, ?)");
			ps.setString(1, name);
			ps.setString(2, dbEntry.getType());
			String conf = dbEntry.getConf();
			ps.setString(3, conf);
			
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
		
		dbEntry.setEnvironmentParamterResolver(envParameterResolver);
		dbEntry.setPasswordResolver(passwordResolver);
		
		publishers.put(name, dbEntry);
	}

	@Override
	public List<PublisherEntry> getPublishersForCA(String caName)
	{
		if(caName == null)
		{
			throw new IllegalArgumentException("caName is null");
		}
		
		Set<String> publisherNames = ca_has_publishers.get(caName);
		if(publisherNames == null)
		{
			return Collections.emptyList();
		}
		
		List<PublisherEntry> ret = new ArrayList<PublisherEntry>(publisherNames.size());
		for(String publisherName : publisherNames)
		{
			ret.add(publishers.get(publisherName));
		}
		
		return ret;
	}

	@Override
	public PublisherEntry getPublisher(String publisherName)
	{
		return publishers.get(publisherName);
	}
	
	@Override
	public void removePublisher(String publisherName)
	throws CAMgmtException
	{
		if(publishers.containsKey(publisherName) == false)
		{
			return;
		}

		for(String caName : ca_has_publishers.keySet()){
			removePublisherFromCA(publisherName, caName);
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("DELETE FROM publisher WHERE name=?");
			ps.setString(1, publisherName);
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
		
		publishers.remove(publisherName);
	}

	@Override
	public void changePublisher(String name, String type, String conf)
	throws CAMgmtException
	{
		if(publishers.containsKey(name))
		{
			throw new CAMgmtException("Could not find publisher " + name);
		}
		
		StringBuilder sb = new StringBuilder();		
		sb.append("UPDATE publisher SET ");
		
		Integer iType = null;
		Integer iConf = null;
		
		int i = 1;
		if(type != null)
		{
			sb.append("type=?,");
			iType = i++;
		}
		if(conf != null)
		{
			sb.append("conf=?,");
			iConf = i++;
		}		
		
		sb.deleteCharAt(sb.length() - 1);
		sb.append(" WHERE name=?");
		
		if(i == 1)
		{
			return;
		}
		int iName = i;
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement(sb.toString());
			if(iType != null)
			{
				ps.setString(iType, getRealString(type));
			}
			
			if(iConf != null)
			{
				ps.setString(iConf, getRealString(conf));
			}
			
			ps.setString(iName, name);
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
	}
		
	@Override
	public CmpControl getCmpControl()
	{
		return cmpControl;
	}
		
	@Override
	public void setCmpControl(CmpControl dbEntry)
	throws CAMgmtException
	{
		if(cmpControl != null)
		{
			removeCmpControl();
		}
		
		cmpControl = dbEntry;

		PreparedStatement ps = null;
		try{
			ps = prepareStatement(
					"INSERT INTO cmpcontrol (name, require_confirm_cert, send_ca_cert, "
					+ " message_time_bias, confirm_wait_time)"
					+ " VALUES (?, ?, ?, ?, ?)");
			
			int idx = 1;
			ps.setString(idx++, CmpControl.name);
			ps.setBoolean(idx++, dbEntry.isRequireConfirmCert());
			ps.setBoolean(idx++, dbEntry.isSendCaCert());
			ps.setInt(idx++, dbEntry.getMessageTimeBias());
			ps.setInt(idx++, dbEntry.getConfirmWaitTime());
	
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
	}

	@Override
	public void removeCmpControl()
	throws CAMgmtException
	{
		if(cmpControl == null)		
		{
			return;
		}
		
		Statement stmt = null;
		try{
			stmt = createStatement();
			stmt.execute("DELETE FROM cmpcontrol");
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(stmt);
		}

		cmpControl = null;		
	}

	@Override
	public void changeCmpControl(Boolean requireConfirmCert, Integer messageTimeBias,
			Integer confirmWaitTime, Boolean sendCaCert)
	throws CAMgmtException
	{
		if(requireConfirmCert == null && messageTimeBias == null && confirmWaitTime == null
				&& sendCaCert == null)
		{
			return;
		}

		if(cmpControl == null)
		{
			throw new CAMgmtException("cmpControl is not initialized");
		}
		
		StringBuilder sb = new StringBuilder();		
		sb.append("UPDATE cmpcontrol SET ");
		
		Integer iConfirmCert = null;
		Integer iMessageTimeBias = null;
		Integer iConfirmWaitTime = null;
		Integer iSenderCaCert = null;
		
		int i = 1;
		if(requireConfirmCert != null)
		{
			sb.append("require_confirm_cert=?,");
			iConfirmCert = i++;
		}
		if(messageTimeBias != null)
		{
			sb.append("message_time_bias=?,");
			iMessageTimeBias = i++;
		}
		if(confirmWaitTime != null)
		{
			sb.append("confirm_wait_time=?,");
			iConfirmWaitTime = i++;
		}
		if(sendCaCert != null)
		{
			sb.append("send_ca_cert=?,");
			iSenderCaCert = i++;
		}
		
		sb.deleteCharAt(sb.length() - 1);
		sb.append(" WHERE name=?");
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement(sb.toString());
			if(iConfirmCert != null)
			{
				ps.setBoolean(iConfirmCert, requireConfirmCert);
			}
			
			if(iMessageTimeBias != null)
			{
				ps.setInt(iMessageTimeBias, messageTimeBias);
			}
			
			if(iConfirmWaitTime != null)
			{
				ps.setInt(iConfirmWaitTime, confirmWaitTime);
			}
			
			if(iSenderCaCert != null)
			{
				ps.setBoolean(iSenderCaCert, sendCaCert);
			}
			
			ps.setString(i, "default");			
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
	}
	
	@Override
	public EnvironmentParameterResolver getEnvParameterResolver()
	{
		return envParameterResolver;
	}
	
	@Override
	public void addEnvParam(String name, String value) throws CAMgmtException
	{
		if(envParameterResolver.getEnvParam(name) != null)
		{
			throw new CAMgmtException("Environemt parameter named " + name + " exists");
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO environment (name, value) VALUES (?, ?)");			
			ps.setString(1, name);
			ps.setString(2, value);			
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
		
		envParameterResolver.addEnvParam(name, value);
	}

	@Override
	public void removeEnvParam(String envParamName)
	throws CAMgmtException
	{
		if(envParameterResolver.getEnvParam(envParamName) == null)
		{
			return;
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("DELETE FROM environment WHERE name=?");
			ps.setString(1, envParamName);
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
		
		envParameterResolver.removeEnvParam(envParamName);
	}

	@Override
	public void changeEnvParam(String name, String value)
	throws CAMgmtException
	{
		ParamChecker.assertNotEmpty("value", value);
		assertNotNULL("value", value);

		if(envParameterResolver.getAllParameterNames().contains(name) == false)
		{
			throw new CAMgmtException("Could not find environment paramter " + name);
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("UPDATE environment SET value=? WHERE name=?");
			ps.setString(1, getRealString(value));
			ps.setString(2, name);
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
	}
		
	static List<String> tokensAsList(String tokens, String seperator)
	{
		StringTokenizer st = new StringTokenizer(tokens, seperator);
		List<String> ret = new ArrayList<String>(st.countTokens());
		while(st.hasMoreTokens())
		{
			ret.add(st.nextToken());
		}
		return ret;
	}

	private static String toString(Set<Permission> permissions)
	{
		if(permissions == null || permissions.isEmpty())
		{
			return null;
		}
		
		StringBuilder sb = new StringBuilder();
		for(Permission p : permissions)
		{
			sb.append(",");
			sb.append(p.getPermission());
		}
		return sb.substring(1); // remove the leading ",".
	}
	
	private static String toString(Set<String> tokens, String seperator)
	{
		if(tokens == null || tokens.isEmpty())
		{
			return null;
		}
		
		StringBuilder sb = new StringBuilder();
		for(String token : tokens)
		{
			sb.append(seperator);
			sb.append(token);
		}
		return sb.substring(seperator.length()); // remove the leading seperator
	}
	
	public static Set<Permission> getPermissions(String permissionsText) 
			throws CAMgmtException
	{
		if(permissionsText == null)
		{
			throw new IllegalArgumentException("permissionsText is null");
		}
		
		List<String> l = tokensAsList(permissionsText, ", ");
		Set<Permission> permissions = new HashSet<Permission>();
		for(String permissionText : l)
		{
			Permission p = Permission.getPermission(permissionText);
			if(p == null)
			{
				throw new CAMgmtException("Unknown permission " + permissionText);
			}
			if(p == Permission.ALL)
			{
				permissions.clear();
				permissions.add(p);
				break;
			}
			else
			{
				permissions.add(p);
			}
		}
		
		return permissions;
	}

	public PasswordResolver getPasswordResolver() {
		return passwordResolver;
	}

	public void setPasswordResolver(PasswordResolver passwordResolver) {
		this.passwordResolver = passwordResolver;
	}
	
	private static String getRealString(String s)
	{
		return NULL.equalsIgnoreCase(s) ? null : s;
	}

	public SecurityFactory getSecurityFactory() {
		return securityFactory;
	}

	public void setSecurityFactory(SecurityFactory securityFactory) {
		this.securityFactory = securityFactory;
	}
	
	public DataSourceFactory getDataSourceFactory() {
		return dataSourceFactory;
	}

	public void setDataSourceFactory(DataSourceFactory dataSourceFactory) {
		this.dataSourceFactory = dataSourceFactory;
	}

	public String getCaConfFile() {
		return caConfFile;
	}

	public void setCaConfFile(String caConfFile) {
		this.caConfFile = caConfFile;
	}

	@Override
	public void addCaAlias(String aliasName, String caName) 
			throws CAMgmtException {
		if(caAliases.get(aliasName) != null)
		{
			throw new CAMgmtException("CA alias " + aliasName + " exists");
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("INSERT INTO caalias (name, ca_name) VALUES (?, ?)");			
			ps.setString(1, aliasName);
			ps.setString(2, caName);			
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
		
		caAliases.put(aliasName, caName);		
	}

	@Override
	public void removeCaAlias(String aliasName) throws CAMgmtException
	{
		if(caAliases.containsKey(aliasName) == false)
		{
			return;
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("DELETE FROM caalias WHERE name=?");
			ps.setString(1, aliasName);
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
		
		caAliases.remove(aliasName);
	}

	@Override
	public String getCaName(String aliasName) {
		return caAliases.get(aliasName);
	}
	
	@Override
	public String getAliasName(String caName)
	{
		for(String alias : caAliases.keySet())
		{
			String thisCaName = caAliases.get(alias);
			if(thisCaName.equals(caName))
			{
				return alias;
			}
		}
		
		return null;
	}

	@Override
	public Set<String> getCaAliasNames() {
		return caAliases.keySet();
	}

	@Override
	public void removeCA(String caname) throws CAMgmtException {
		if(cas.containsKey(caname) == false)
		{
			return;
		}
		
		PreparedStatement ps = null;
		try{
			ps = prepareStatement("DELETE FROM ca WHERE name=?");
			ps.setString(1, caname);
			ps.executeUpdate();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}finally
		{
			closeStatement(ps);
		}
		
		cas.remove(caname);
	}

	@Override
	public void publishRootCA(String caname) throws CAMgmtException {
		X509CA ca = x509cas.get(caname);
		if(ca == null)
		{
			throw new CAMgmtException("Cannot find CA named " + caname);
		}
		
		X509CertificateWithMetaInfo certInfo = ca.getCAInfo().getCertificate();
		if(certInfo.getCert().getSubjectX500Principal().equals(
				certInfo.getCert().getIssuerX500Principal()) == false)
		{
			throw new CAMgmtException("CA named " + caname + " is not a self-signed CA");
		}
		
		byte[] encodedSubjectPublicKey = certInfo.getCert().getPublicKey().getEncoded();
		CertificateInfo ci;
		try {
			ci = new CertificateInfo(
					certInfo, certInfo, encodedSubjectPublicKey, "UNKNOWN-Profile");
		} catch (CertificateEncodingException e) {
			throw new CAMgmtException(e);
		}
		ca.publishCertificate(ci);		
	}

	private static void assertNotNULL(String parameterName, String parameterValue)
	{
		if(NULL.equalsIgnoreCase(parameterValue))
		{
			throw new IllegalArgumentException(parameterName + " could not be " + NULL);
		}
	}
	
	
	private Statement createStatement() throws CAMgmtException
	{
		try{
			if(dsConnection == null || dsConnection.isClosed())
			{
				dsConnection = dataSource.getConnection(0);
			}
			
			if(dsConnection == null || dsConnection.isClosed())
			{
				throw new CAMgmtException("Could not get connection");
			}
			
			return dsConnection.createStatement();
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}
	}
	
	private PreparedStatement prepareStatement(String sql) throws CAMgmtException
	{
		try{
			if(dsConnection == null || dsConnection.isClosed())
			{
				dsConnection = dataSource.getConnection(0);
			}
			
			if(dsConnection == null || dsConnection.isClosed())
			{
				throw new CAMgmtException("Could not get connection");
			}
			
			return dsConnection.prepareStatement(sql);
		}catch(SQLException e)
		{
			throw new CAMgmtException(e);
		}
	}

	@Override
	public boolean republishCertificates(String caname, String publisherName)
			throws CAMgmtException 
	{
		X509CA ca = x509cas.get(caname);
		if(ca == null)
		{
			throw new CAMgmtException("Cannot find CA named " + caname);
		}

		return ca.republishCertificates(publisherName);
	}
	
}
