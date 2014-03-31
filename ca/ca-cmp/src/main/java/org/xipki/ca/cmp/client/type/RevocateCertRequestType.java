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

package org.xipki.ca.cmp.client.type;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class RevocateCertRequestType 
{
	private final List<RevocateCertRequestEntryType> requestEntries = new LinkedList<RevocateCertRequestEntryType>();

	public boolean addRequestEntry(RevocateCertRequestEntryType requestEntry)
	{
		for(RevocateCertRequestEntryType re : requestEntries)
		{
			if(re.getId().equals(requestEntry.getId()))
			{
				return false;
			}
		}
		
		requestEntries.add(requestEntry);
		return true;
	}
	
	public List<RevocateCertRequestEntryType> getRequestEntries()
	{
		return Collections.unmodifiableList(requestEntries);
	}
}
