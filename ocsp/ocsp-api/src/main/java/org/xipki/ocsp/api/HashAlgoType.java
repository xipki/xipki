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

package org.xipki.ocsp.api;

public enum HashAlgoType {
	SHA1  (20, "1.3.14.3.2.26"),
	SHA224(28, "2.16.840.1.101.3.4.2.4"),
	SHA256(32, "2.16.840.1.101.3.4.2.1"),
	SHA384(48, "2.16.840.1.101.3.4.2.2"),
	SHA512(64, "2.16.840.1.101.3.4.2.3");
    
	private final int length;
	private final String oid;
	
	private HashAlgoType(int length, String oid)
	{
		this.length = length;
		this.oid = oid;
	}
	
	public int getLength()
	{
		return length;
	}
	
	public String getOid()
	{
		return oid;
	}
	
	public static HashAlgoType getHashAlgoType(String oid)
	{
		for(HashAlgoType hashAlgo : values())
		{
			if(hashAlgo.oid.equals(oid))
			{
				return hashAlgo;
			}
		}
		
		return null;
	}
}
