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

package org.xipki.ca.api.publisher;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.EnvironmentParameterResolver;

public interface CertPublisher{
	void initialize(String conf, PasswordResolver passwordResolver,
			DataSourceFactory dataSourceFactory) 
			throws CertPublisherException;
	
	void setEnvironmentParamterResolver(EnvironmentParameterResolver paramterResolver);
	
	void certificateAdded(CertificateInfo certInfo);

	void certificateRevoked(X509Certificate cert, 
			int reason, Date invalidityTime);

	void certificateRevoked(String issuer, BigInteger serialNumber,
			int reason, Date invalidityTime);	
	
	void crlAdded(X509CertificateWithMetaInfo cacert, X509CRL crl);
}
