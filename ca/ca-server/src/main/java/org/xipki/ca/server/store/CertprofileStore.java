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

package org.xipki.ca.server.store;

import java.util.HashMap;
import java.util.Map;

import org.xipki.security.common.ParamChecker;

class CertprofileStore {
	private final Map<String, Integer> entries;
	private int nextFreeId;
	
	CertprofileStore(Map<String, Integer> entries)
	{
		this.entries = new HashMap<String, Integer>();
		
		for(String name : entries.keySet()) {
			addProfileEntry(name, entries.get(name));
		}
		
		if(nextFreeId < 1)
		{
			nextFreeId = 1;
		}
	}
	
	synchronized void addProfileEntry(String name, Integer id)
	{
		ParamChecker.assertNotEmpty("name", name);
		ParamChecker.assertNotNull("id", id);
		
		if(entries.containsKey(name))
		{
			throw new IllegalArgumentException("certprofile with the same name " + name + " already available");
		}
		
		if(entries.containsValue(id))
		{
			throw new IllegalArgumentException("certprofile with the same id " + id + " already available");
		}
		
		if(nextFreeId <= id) {
			nextFreeId = id + 1;
		}
		
		entries.put(name, id);
	}
	
	synchronized Integer getId(String name)
	{
		return entries.get(name);
	}

	synchronized int getNextFreeId(){
		return nextFreeId++;
	}

}
