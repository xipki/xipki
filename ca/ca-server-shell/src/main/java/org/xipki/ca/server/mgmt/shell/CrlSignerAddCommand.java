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

package org.xipki.ca.server.mgmt.shell;

import java.security.cert.X509Certificate;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.server.mgmt.CrlSignerEntry;
import org.xipki.security.common.IoCertUtil;

@Command(scope = "ca", name = "crlsigner-add", description="Add CRL signer")
public class CrlSignerAddCommand extends CaCommand {
	@Option( name = "-name",
	         description = "Required. CRL signer name",
	         required = true, multiValued = false)
	protected String            name;

	@Option(name = "-signerType",
            description = "Required. CRL signer type, use 'CA' to sign the CRL by the CA itself",
            required = true)
    protected String            signerType;

	@Option(name = "-signerConf",
            description = "CRL signer configuration")
    protected String            signerConf;

	@Option(name = "-cert",
            description = "CRL signer's certificate file")
    protected String            signerCert;
	
	@Option(name = "-period",
            required=true, description = "Required. Interval in minutes of two CRLs, set to 0 to generate CRL on demand")
    protected Integer            period;
	
	@Option(name = "-overlap",
            description = "Overlap of CRL")
    protected Integer            overlap;
	
	@Option(name = "-ewc", aliases = { "--enableWithCerts" },
            description = "Certificates are contained in the CRL, the default is not")
    protected Boolean            enableWithCerts;
	
	@Option(name = "-dwc", aliases = { "--disableWithCerts" },
            description = "Certificates are not contained in the CRL, the default is not")
    protected Boolean            disableWithCerts;
	
    @Override
    protected Object doExecute() throws Exception {
    	CrlSignerEntry entry = new CrlSignerEntry(name);
    	entry.setType(signerType);
    	if(signerConf != null)
    	{
    		entry.setConf(signerConf);
    	}
    	if(signerCert != null)
    	{
    		X509Certificate cert = IoCertUtil.parseCert(signerCert);
    		entry.setCert(cert);
    	}
    	entry.setPeriod(period);
    	
    	if(overlap != null)
    	{
    		entry.setOverlap(overlap);
    	}
    	
    	if(enableWithCerts != null && disableWithCerts != null )
    	{
    		System.err.println("Containing certificates in CRL could not be enabled and disabled at the same time");
    	}
    	boolean withCerts = isEnabled(enableWithCerts, disableWithCerts, false);    			
    	entry.setIncludeCertsInCrl(withCerts);
    	caManager.addCrlSigner(entry);
    	
    	return null;
    }
}
