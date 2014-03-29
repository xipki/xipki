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

package org.xipki.ocsp;

import java.util.ArrayList;
import java.util.List;

import org.xipki.ocsp.api.HashAlgoType;

public class IssuerStore {
	private final List<IssuerEntry> entries;
	
	public IssuerStore(List<IssuerEntry> entries)
	{
		this.entries = new ArrayList<IssuerEntry>(entries.size());
		
		for(IssuerEntry entry : entries) {
			for(IssuerEntry existingEntry : this.entries) {
				if(existingEntry.getId() == entry.getId()) {
					throw new IllegalArgumentException("issuer with the same id " + entry.getId() + " already available");
				}
			}
			this.entries.add(entry);
		}
	}
	
	public Integer getIssuerIdForSubject(String subject)
	{
		IssuerEntry issuerEntry = getIssuerForSubject(subject);
		return issuerEntry == null ? null : issuerEntry.getId();
	}
	
	public IssuerEntry getIssuerForSubject(String subject)
	{
		for(IssuerEntry entry : entries) {
			if(entry.getSubject().equals(subject))
			{
				return entry;
			}
		}
		
		return null;
	}

	public Integer getIssuerIdForFp( HashAlgoType hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash)
	{
		IssuerEntry issuerEntry = getIssuerForFp(hashAlgo, issuerNameHash, issuerKeyHash);
		return issuerEntry == null ? null : issuerEntry.getId();
	}
		
	public IssuerEntry getIssuerForFp( HashAlgoType hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash)
	{
		for(IssuerEntry entry : entries) {
			if(entry.matchHash(hashAlgo, issuerNameHash, issuerKeyHash))
			{
				return entry;
			}
		}
		
		return null;
	}

}
