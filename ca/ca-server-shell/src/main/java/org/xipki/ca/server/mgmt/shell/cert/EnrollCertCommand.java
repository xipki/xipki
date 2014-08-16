/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell.cert;

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

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "enroll-cert", description="Enroll certificate")
public class EnrollCertCommand extends CaCertCommand
{
    private static final Logger LOG = LoggerFactory.getLogger(EnrollCertCommand.class);

    @Option(name = "-ca",
            required = true, description = "Required. CA name")
    protected String            caName;

    @Option(name = "-p10",
            required = true, description = "Required. PKCS#10 request file")
    protected String            p10File;

    @Option(name = "-out",
            description = "Required. Where to save the certificate",
            required = true)
    protected String            outFile;

    @Option(name = "-profile",
            required = true, description = "Required. Profile name")
    protected String            profileName;

    @Option(name = "-user",
            required = false, description = "Username")
    protected String            user;

    private SecurityFactory securityFactory;

    public SecurityFactory getSecurityFactory()
    {
        return securityFactory;
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    @Override
    protected Object doExecute()
    throws Exception
    {
        X509CA ca = caManager.getX509CA(caName);
        if(ca == null)
        {
            System.err.println("CA " + caName + " not available");
            return null;
        }

        CertificationRequest p10cr;
        try
        {
            byte[] encodedP10Request = IoCertUtil.read(p10File);
            p10cr = CertificationRequest.getInstance(encodedP10Request);
        }catch(Exception e)
        {
            System.err.println("Parsing PKCS#10 request. ERROR: " + e.getMessage());
            return null;
        }

        if(securityFactory.verifyPOPO(p10cr) == false)
        {
            System.err.print("could not validate POP for the pkcs#10 requst");
            return null;
        }
        else
        {
            CertificationRequestInfo certTemp = p10cr.getCertificationRequestInfo();
            Extensions extensions = null;
            ASN1Set attrs = certTemp.getAttributes();
            for(int i = 0; i < attrs.size(); i++)
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
            try
            {
                certInfo = ca.generateCertificate(false, profileName, user, subject, publicKeyInfo,
                        null, null, extensions);
                ca.publishCertificate(certInfo);
                saveVerbose("Saved certificate to file", new File(outFile), certInfo.getCert().getEncodedCert());
            } catch (Exception e)
            {
                LOG.warn("Exception: {}", e.getMessage());
                LOG.debug("Exception", e);
                System.err.println("ERROR: " + e.getMessage());
                return null;
            }
        }

        return null;
    }

}
