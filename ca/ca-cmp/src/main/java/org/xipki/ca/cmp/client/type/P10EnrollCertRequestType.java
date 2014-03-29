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

package org.xipki.ca.cmp.client.type;

import org.bouncycastle.asn1.pkcs.CertificationRequest;

public class P10EnrollCertRequestType extends IdentifiedObject
{
	private final String certProfile;
	private final CertificationRequest p10Req;
	
	public P10EnrollCertRequestType(String id, String certProfile, CertificationRequest p10Req)
	{
		super(id);
		if(p10Req == null)
			throw new IllegalArgumentException("p10Req is null");
				
		this.certProfile = certProfile;

		this.p10Req = p10Req;
	}	
	
	public CertificationRequest getP10Req()
	{
		return p10Req;
	}	
	
	public String getCertProfile() {
		return certProfile;
	}
}
