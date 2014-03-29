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

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.server.mgmt.CmpResponderEntry;
import org.xipki.security.common.IoCertUtil;

@Command(scope = "ca", name = "responder-set", description="Set responder")
public class ResponderSetCommand extends CaCommand {
	@Option(name = "-signerType",
            description = "Required. Type of the responder signer",
            required = true)
    protected String            signerType;

	@Option(name = "-signerConf",
            description = "Conf of the responder signer")
    protected String            signerConf;

	@Option(name = "-cert",
            description = "Requestor certificate, in form of 'file:<path> or base64:<content>")
    protected String            certFile;

    @Override
    protected Object doExecute() throws Exception {
		CmpResponderEntry entry = new CmpResponderEntry();		
		if(certFile != null)
		{
			entry.setCert(IoCertUtil.parseCert(certFile));
		}
		entry.setType(signerType);
		
		if("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType))
		{
			signerConf = ShellUtil.replaceFileInSignerConf(signerConf);
		}
		
		entry.setConf(signerConf);
		
		caManager.setCmpResponder(entry);
		
    	return null;
    }
}
