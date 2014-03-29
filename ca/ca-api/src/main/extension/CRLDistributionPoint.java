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

package lca.ca.profile.extension;

import java.util.Set;

public class CRLDistributionPoint extends ExtensionConf {
	private String distributionPoint;
	private String crlIssuer;
	private Set<java.security.cert.CRLReason> crlReasons;
	
	public Set<java.security.cert.CRLReason> getCrlReasons() {
		return crlReasons;
	}

	public void setCrlReasons(Set<java.security.cert.CRLReason> crlReasons) {
		this.crlReasons = crlReasons;
	}

	public void setDistributionPoint(String distributionPoint) {
		this.distributionPoint = distributionPoint;
	}

	public void setCrlIssuer(String crlIssuer) {
		this.crlIssuer = crlIssuer;
	}

	public String getDistributionPoint() {
		return distributionPoint;
	}

	public Set<java.security.cert.CRLReason> getReasons() {
		return crlReasons;
	}

	public String getCrlIssuer() {
		return crlIssuer;
	}

}
