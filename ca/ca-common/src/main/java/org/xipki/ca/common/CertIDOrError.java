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

package org.xipki.ca.common;

import org.bouncycastle.asn1.crmf.CertId;
import org.xipki.security.common.ParamChecker;

public class CertIDOrError {
	private final CertId certId;
	private final PKIStatusInfo error;
	
	public CertIDOrError(CertId certId) {
		ParamChecker.assertNotNull("certId", certId);

		this.certId = certId;
		this.error = null;
	}

	public CertIDOrError(PKIStatusInfo error) {
		ParamChecker.assertNotNull("error", error);

		this.certId = null;
		this.error = error;
	}

	public CertId getCertId() {
		return certId;
	}

	public PKIStatusInfo getError() {
		return error;
	}

	
}
