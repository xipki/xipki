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

package org.xipki.ca.api.profile;


public enum KeyUsage {
	digitalSignature (0, "digitalSignature"),
	contentCommitment (1, "contentCommitment", "nonRepudiation"), 
	keyEncipherment (2, "keyEncipherment"),
	dataEncipherment (3, "dataEncipherment"),
	keyAgreement (4, "keyAgreement"),
	keyCertSign (5, "keyCertSign"),
	cRLSign (6, "cRLSign"),
	encipherOnly (7, "encipherOnly"),
	decipherOnly (8, "decipherOnly");

	private int bit;
	private String[] names;
	private KeyUsage(int bit, String... names)
	{
		this.bit = bit;
		this.names = names;
	}
	
	public static KeyUsage getKeyUsage(String usage)
	{
		if(usage == null)
		{
			return null;
		}
		
		for(KeyUsage ku : KeyUsage.values())
		{
			for(String name : ku.names)
			{
				if(name.equals(usage))
				{
					return ku;
				}
			}
		}
		
		return null;
	}
	
	public static KeyUsage getKeyUsage(int bit)
	{
		for(KeyUsage ku : KeyUsage.values())
		{
			if(ku.bit == bit)
			{
				return ku;
			}
		}
		
		return null;
	}
}
