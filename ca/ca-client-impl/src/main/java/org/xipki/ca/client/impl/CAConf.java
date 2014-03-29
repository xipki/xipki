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

package org.xipki.ca.client.impl;

import java.security.cert.X509Certificate;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.security.common.ParamChecker;

class CAConf
{
	private final String name;
	private final String url;
	private final X509Certificate cert;
	private final X509Certificate responder;
	private final X500Name subject;
	private final Set<String> profiles;
	
	CAConf(String name, String url, X509Certificate cert, Set<String> profiles, X509Certificate responder) 
	{
		ParamChecker.assertNotEmpty("name", name);
		ParamChecker.assertNotEmpty("url", url);
		ParamChecker.assertNotNull("cert", cert);
		ParamChecker.assertNotEmpty("profiles", profiles);
		ParamChecker.assertNotNull("responder", responder);
		
		this.name = name;
		this.url = url;
		this.cert = cert;
		this.subject = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
		this.profiles = profiles;
		this.responder = responder;
	}

	public String getName() {
		return name;
	}

	public String getUrl() {
		return url;
	}

	public X509Certificate getCert() {
		return cert;
	}

	public X500Name getSubject() {
		return subject;
	}

	public Set<String> getProfiles() {
		return profiles;
	}

	public X509Certificate getResponder() {
		return responder;
	}		
}
