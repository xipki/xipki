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

package org.xipki.ca.server;

import org.xipki.security.api.ConcurrentContentSigner;

public class CrlSigner {
	private final ConcurrentContentSigner signer;
	private final int period;
	private final int overlap;	
	private boolean includeCertsInCrl;
	
	public CrlSigner(ConcurrentContentSigner signer, int period, int overlap) {
		super();
		this.signer = signer;
		this.period = period;
		this.overlap = overlap;
	}

	public ConcurrentContentSigner getSigner() {
		return signer;
	}

	public int getPeriod() {
		return period;
	}

	public int getOverlap() {
		return overlap;
	}

	public boolean includeCertsInCrl() {
		return includeCertsInCrl;
	}

	public void setIncludeCertsInCrl(boolean includeCertsInCrl) 
	{
		this.includeCertsInCrl = includeCertsInCrl;		
	}

}
