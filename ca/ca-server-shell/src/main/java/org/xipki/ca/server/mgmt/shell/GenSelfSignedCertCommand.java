/*
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.server.mgmt.shell;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.api.profile.CertProfile;
import org.xipki.ca.server.IdentifiedCertProfile;
import org.xipki.ca.server.RandomSerialNumberGenerator;
import org.xipki.ca.server.mgmt.shell.SelfSignedCertBuilder.GenerateSelfSignedResult;
import org.xipki.console.karaf.XipkiOsgiCommandSupport;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "gen-selfsign-cert", description="Generate selfsigned certificate")
public class GenSelfSignedCertCommand extends XipkiOsgiCommandSupport
{
    @Option(name = "-subject",
            description = "Required. Subject of the certificate",
            required = true)
    protected String           subject;

    @Option(name = "-profileClass",
            description = "Required. Profile class name",
            required = true)
    protected String           profileClass;

    @Option(name = "-profileConf",
            description = "Profile configuration",
            required = false)
    protected String           profileConf;

    @Option(name = "-out",
            description = "Required. Where to save the generated certificate",
            required = true)
    protected String certOutFile;

    @Option(name = "-ocspUri",
            description = "OCSP URI, multi options is allowed",
            multiValued = true)
    protected List<String> ocspUris;

    @Option(name = "-crlUri",
            description = "CRL URI, multi options is allowed",
            multiValued = true)
    protected List<String> crlUris;

    @Option(name = "-signerType",
            description = "Required. Signer type",
            required = true)
    protected String            signerType;

    @Option(name = "-signerConf",
            description = "Signer configuration")
    protected String            signerConf;

    @Option(name = "-serial",
            description = "Required. Serial number for the certificate, 0 for random serial number",
            required = true)
    protected Long            serial;

    private PasswordResolver passwordResolver;
    private SecurityFactory securityFactory;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(serial < 0)
        {
            System.err.println("invalid serial number: " + serial);
            return null;
        }
        else if(serial == 0)
        {
            serial = RandomSerialNumberGenerator.getInstance().getSerialNumber().longValue();
        }

        IdentifiedCertProfile certProfile;
        try
        {
            CertProfile cp = (CertProfile) Class.forName(profileClass).newInstance();
            certProfile = new IdentifiedCertProfile("dummy", cp);
        }catch(Exception e)
        {
            System.err.println("Invalid cert profile configuration");
            return null;
        }

        GenerateSelfSignedResult result = SelfSignedCertBuilder.generateSelfSigned(
                securityFactory, passwordResolver, signerType, signerConf,
                certProfile, subject, serial, ocspUris, crlUris);

        File outFile = new File(certOutFile);
        X509Certificate caCert = result.getCert();
        saveVerbose("Saved self-signed certificate to file", outFile, caCert.getEncoded());

        return null;
    }

    public void setPasswordResolver(PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }
}
