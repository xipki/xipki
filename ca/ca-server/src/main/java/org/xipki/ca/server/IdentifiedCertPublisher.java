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

package org.xipki.ca.server;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.EnvironmentParameterResolver;
import org.xipki.security.common.ParamChecker;

public class IdentifiedCertPublisher implements CertPublisher {
	private final String name;
	private final CertPublisher certPublisher;
	
	public IdentifiedCertPublisher(String name, CertPublisher certPublisher)
	{
		ParamChecker.assertNotEmpty("name", name);
		ParamChecker.assertNotNull("certPublisher", certPublisher);
		
		this.name = name;
		this.certPublisher = certPublisher;		
	}

	@Override
	public void initialize(String conf, PasswordResolver passwordResolver, 
			DataSourceFactory dataSourceFactory) 
	throws CertPublisherException {
		certPublisher.initialize(conf, passwordResolver, dataSourceFactory);
	}

	@Override
	public void setEnvironmentParamterResolver(EnvironmentParameterResolver paramterResolver) {
		certPublisher.setEnvironmentParamterResolver(paramterResolver);		
	}

	@Override
	public void certificateAdded(CertificateInfo certInfo) {
		certPublisher.certificateAdded(certInfo);
	}

	@Override
	public void certificateRevoked(X509Certificate cert, int reason, Date invalidityTime) {
		certPublisher.certificateRevoked(cert, reason, invalidityTime);
	}

	@Override
	public void certificateRevoked(String issuer, BigInteger serialNumber, int reason, Date invalidityTime) {
		certPublisher.certificateRevoked(issuer, serialNumber, reason, invalidityTime);
	}

	@Override
	public void crlAdded(X509CertificateWithMetaInfo cacert, X509CRL crl) {
		certPublisher.crlAdded(cacert, crl);
	}

	public String getName() {
		return name;
	}

	@Override
	public boolean isHealthy() {
		return certPublisher.isHealthy();
	}
}
