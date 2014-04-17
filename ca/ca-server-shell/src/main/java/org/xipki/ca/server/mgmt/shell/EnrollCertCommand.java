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

package org.xipki.ca.server.mgmt.shell;

import java.io.File;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.server.X509CA;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.IoCertUtil;

@Command(scope = "ca", name = "enroll", description="Enroll certificate")
public class EnrollCertCommand extends CaCommand {
    private static final Logger LOG = LoggerFactory.getLogger(EnrollCertCommand.class);

    @Option(name = "-ca",
            required = true, description = "Required. CA name")
    protected String            caName;

    @Option(name = "-p10",
            required = true, description = "Required. PKCS-10 request file")
    protected String            p10File;

    @Option(name = "-out",
            description = "Required. Where to save the certificate",
            required = true)
    protected String            outFile;

    @Option(name = "-profile",
            required = true, description = "Required. Profile name")
    protected String            profileName;

    private SecurityFactory securityFactory;

    public SecurityFactory getSecurityFactory() {
        return securityFactory;
    }

    public void setSecurityFactory(SecurityFactory securityFactory) {
        this.securityFactory = securityFactory;
    }

    @Override
    protected Object doExecute() throws Exception {
        X509CA ca = caManager.getX509CA(caName);
        if(ca == null)
        {
            System.err.println("CA " + caName + " not available");
            return null;
        }

        CertificationRequest p10cr;
        try{
            byte[] encodedP10Request = IoCertUtil.read(p10File);
            p10cr = CertificationRequest.getInstance(encodedP10Request);
        }catch(Exception e)
        {
            System.err.println("Parsing PKCS#10 request. ERROR: " + e.getMessage());
            return null;
        }

        if(! securityFactory.verifyPOPO(p10cr))
        {
            System.err.print("could not validate POP for the pkcs#10 requst");
            return null;
        }
        else
        {
            CertificationRequestInfo certTemp = p10cr.getCertificationRequestInfo();
            Extensions extensions = null;
            ASN1Set attrs = certTemp.getAttributes();
            for(int i=0; i<attrs.size(); i++)
            {
                Attribute attr = (Attribute) attrs.getObjectAt(i);
                if(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType()))
                {
                    extensions = (Extensions) attr.getAttributeValues()[0];
                }
            }

            X500Name subject = certTemp.getSubject();
            SubjectPublicKeyInfo publicKeyInfo = certTemp.getSubjectPublicKeyInfo();

            CertificateInfo certInfo;
            try {
                certInfo = ca.generateCertificate(false, profileName, null, subject, publicKeyInfo,
                        null, null, extensions);
                ca.publishCertificate(certInfo);
                IoCertUtil.save(new File(outFile), certInfo.getCert().getEncodedCert());
            } catch (Exception e) {
                LOG.warn("Exception: {}", e.getMessage());
                LOG.debug("Exception", e);
                System.err.println("ERROR: " + e.getMessage());
                return null;
            }
        }

        return null;
    }

}
