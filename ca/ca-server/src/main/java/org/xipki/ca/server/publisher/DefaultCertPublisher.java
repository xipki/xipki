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

package org.xipki.ca.server.publisher;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.database.api.DataSource;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.EnvironmentParameterResolver;
import org.xipki.security.common.ParamChecker;

public class DefaultCertPublisher implements CertPublisher {	
	private static final Logger LOG = LoggerFactory.getLogger(DefaultCertPublisher.class);
	
	@SuppressWarnings("unused")
	private EnvironmentParameterResolver envParamterResolver;
	private CertStatusStoreQueryExecutor queryExecutor;
	
	public DefaultCertPublisher()
	{		
	}
	
	@Override
	public void initialize(String conf, PasswordResolver passwordResolver, 
			DataSourceFactory dataSourceFactory)
			throws CertPublisherException
	{
		ParamChecker.assertNotNull("dataSourceFactory", dataSourceFactory);
		
		byte[] confBytes;
		if(conf.startsWith("base64:"))
		{
			String b64Conf = conf.substring("base64:".length());
			confBytes = Base64.decode(b64Conf);
		}
		else
		{
			confBytes = conf.getBytes();
		}
		InputStream confStream = new ByteArrayInputStream(confBytes);
		
		DataSource dataSource;
		try {
			dataSource = dataSourceFactory.createDataSource(confStream, passwordResolver);
		} catch (IOException e) {
			throw new CertPublisherException(e);
		} catch (SQLException e) {
			throw new CertPublisherException(e);
		} catch (PasswordResolverException e) {
			throw new CertPublisherException(e);
		}
		
		try {
			queryExecutor = new CertStatusStoreQueryExecutor(dataSource);
		} catch (NoSuchAlgorithmException e) {
			throw new CertPublisherException(e);
		} catch (SQLException e) {
			throw new CertPublisherException(e);
		}
	}

	@Override
	public void setEnvironmentParamterResolver(
			EnvironmentParameterResolver paramterResolver)
	{
		this.envParamterResolver = paramterResolver;
	}

	@Override
	public void certificateAdded(CertificateInfo certInfo)
	{
		try {
			if(certInfo.isRevocated())
			{
				queryExecutor.addCert(certInfo.getIssuerCert(), 
						certInfo.getCert(),
						certInfo.getProfileName(),
						certInfo.isRevocated(),
						certInfo.getRevocationTime(),
						certInfo.getRevocationReason(),
						certInfo.getInvalidityTime());
			}
			else
			{
				queryExecutor.addCert(certInfo.getIssuerCert(), 
						certInfo.getCert(),
						certInfo.getProfileName());
			}
		} catch (Exception e) {			
			LOG.error("Could not save certificate {}: {}. Message: {}",
					new Object[]{certInfo.getCert().getSubject(),
					Base64.toBase64String(certInfo.getCert().getEncodedCert()), e.getMessage()});
			LOG.error("error", e);
		}
	}

	@Override
	public void certificateRevoked(X509Certificate cert, int reason,
			Date invalidityTime)
	{
		try {
			queryExecutor.revocateCert(cert, new Date(), reason, invalidityTime);
		} catch (SQLException e) {
			LOG.error("Could not revocate certificate {}: {}",
					cert.getSubjectX500Principal(),
					e.getMessage());
		}
	}

	@Override
	public void certificateRevoked(X500Principal issuer, BigInteger serialNumber,
			int reason, Date invalidityTime)
	{
		try {
			queryExecutor.revocateCert(issuer, serialNumber, new Date(), reason, invalidityTime);
		} catch (SQLException e) {
			LOG.error("Could not revocate certificate issuer={}, serial={}: {}",
					new Object[]{issuer, serialNumber, e.getMessage()});
		}
	}

	@Override
	public void crlAdded(X509CertificateWithMetaInfo cacert, X509CRL crl)
	{
	}

	@Override
	public boolean isHealthy() {
		return queryExecutor.isHealthy();
	}

}
