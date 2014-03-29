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

package org.xipki.ca.server.publisher;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.util.encoders.Hex;

class HashCalculator {
	private MessageDigest sha1;
	private MessageDigest sha224;
	private MessageDigest sha256;
	private MessageDigest sha384;
	private MessageDigest sha512;
	
	public HashCalculator() throws NoSuchAlgorithmException
	{
		sha1   = MessageDigest.getInstance("SHA-1");
		sha224 = MessageDigest.getInstance("SHA-224");
		sha256 = MessageDigest.getInstance("SHA-256");
		sha384 = MessageDigest.getInstance("SHA-384");
		sha512 = MessageDigest.getInstance("SHA-512");
	}
	
	public String hexHash(HashAlgoType hashAlgoType, byte[] data)
	{
		byte[] bytes = hash(hashAlgoType, data);
		return bytes == null ? null : Hex.toHexString(bytes).toUpperCase();
	}
	
	public byte[] hash(HashAlgoType hashAlgoType, byte[] data)
	{
		MessageDigest md;
		switch(hashAlgoType)
		{
			case SHA1:
				md = sha1;
				break;
			case SHA224:
				md = sha224;
				break;
			case SHA256:
				md = sha256;
				break;
			case SHA384:
				md = sha384;
				break;
			case SHA512:
				md = sha512;
				break;
			default:
				throw new RuntimeException("should not reach here");
		}
		
		synchronized (md) {
			md.reset();
			return md.digest(data);
		}
	}
}
