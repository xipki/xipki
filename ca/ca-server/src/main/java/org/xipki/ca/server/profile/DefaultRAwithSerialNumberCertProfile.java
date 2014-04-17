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

package org.xipki.ca.server.profile;


/**
 * This profile will be used if the requestor is registered as RA. It will be accepted by all 
 * CAs without explicit configuration. It accepts all from the request except the 
 * extensions AuthorityKeyIdentifier, SubjectKeyIdentifier, CRLDistributionPoint and AuthorityInfoAccess.
 * It adds or increases the RDN serialNumber to the Subject with unique number if the same subject already exists.
 *
 */
public class DefaultRAwithSerialNumberCertProfile extends DefaultRACertProfile
{
	@Override
	public boolean incSerialNumberIfSubjectExists() {
		return true;
	}
}
