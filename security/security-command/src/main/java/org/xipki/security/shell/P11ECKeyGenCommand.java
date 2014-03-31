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

package org.xipki.security.shell;

import java.io.File;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.api.P11KeypairGenerationResult;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.p11.iaik.IaikP11CryptService;
import org.xipki.security.p11.iaik.P11KeypairGenerator;

@Command(scope = "keytool", name = "ec", description="Generate EC keypair in PKCS#11 device")
public class P11ECKeyGenCommand extends OsgiCommandSupport {
	@Option(name = "-curve",
			description = "EC Curve name, the default is brainpoolP256r1",
			required = false)
    protected String            curveName;
	
	@Option(name = "-slot",
			required = true, description = "Required. Slot index")
    protected Integer           slotIndex;
	
	@Option(name = "-label",
			required = true, description = "Required. Label of the PKCS#11 objects")
    protected String            label;
	
	@Option(name = "-pwd", aliases = { "--password" },
			required = false, description = "Password of the PKCS#11 token")
    protected String            password;
	
	@Option(name = "-out",
			required = false, description = "Output file name of certificate")
    protected String            outputFilename;
	
	private SecurityFactory securityFactory;
	
	public SecurityFactory getSecurityFactory() {
		return securityFactory;
	}

	public void setSecurityFactory(SecurityFactory securityFactory) {
		this.securityFactory = securityFactory;
	}
	
    @Override
    protected Object doExecute() throws Exception {
    	if(curveName == null)
    	{
    		curveName = "brainpoolP256r1";
    	}
    	
    	char[] pwd = (password == null) ? new char[]{'1', '2', '3', '4'} : password.toCharArray();
    	
    	P11KeypairGenerator gen = new P11KeypairGenerator();
    	P11KeypairGenerationResult keyAndCert = gen.generateECDSAKeypairAndCert(
    			securityFactory.getPkcs11Module(), new PKCS11SlotIdentifier(slotIndex, null), pwd,
    			curveName, label, "CN=" + label);
    	
    	System.out.println("key id: " + Hex.toHexString(keyAndCert.getId()));
    	System.out.println("key label: " + keyAndCert.getLabel());
    	if(outputFilename != null)
    	{
	   		File certFile = new File(outputFilename);
	   		IoCertUtil.save(certFile, keyAndCert.getCertificate().getEncoded());
	   		System.out.println("Saved self-signed certificate in " + certFile.getPath());
    	}
    	
    	IaikP11CryptService.getInstance(securityFactory.getPkcs11Module(), pwd).refresh();
    	
    	return null;
    }

}
