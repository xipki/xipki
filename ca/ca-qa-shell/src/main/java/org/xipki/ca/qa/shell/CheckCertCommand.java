/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.ca.qa.shell;

import java.util.Set;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extensions;
import org.xipki.ca.api.EnvironmentParameterResolver;
import org.xipki.ca.qa.ValidationIssue;
import org.xipki.ca.qa.ValidationResult;
import org.xipki.ca.qa.X509CertProfileQA;
import org.xipki.ca.qa.X509IssuerInfo;
import org.xipki.common.IoUtil;
import org.xipki.console.karaf.XipkiOsgiCommandSupport;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-qa", name = "check-cert", description="Check the certificate")
public class CheckCertCommand extends XipkiOsgiCommandSupport
{
    @Option(name = "-cert",
            required = true, description = "Required. Certificate file")
    protected String certFile;

    @Option(name = "-issuer",
            required = false, description = "Required if multiple issuers are configured. Issuer name")
    protected String issuerName;

    @Option(name = "-env",
            required = false, description = "Environment name")
    protected String envName;

    @Option(name = "-p10",
            required = true, description = "Required. PKCS#10 request file")
    protected String p10File;

    @Option(name = "-profile",
            required = true, description = "Required. Certificate profile")
    protected String profileName;

    @Option(name = "-v", aliases="--verbose",
            required = false, description = "Show status verbosely")
    protected Boolean verbose = Boolean.FALSE;

    private QASystemManager qaSystemManager;

    @Override
    protected Object doExecute()
    throws Exception
    {
        Set<String> issuerNames = qaSystemManager.getIssuerNames();
        if(issuerNames.isEmpty())
        {
            err("No issuer is configured");
            return  null;
        }

        if(issuerName == null)
        {
            if(issuerNames.size() != 1)
            {
                err("No issuer is specified");
                return null;
            }

            issuerName = issuerNames.iterator().next();
        }

        if(issuerNames.contains(issuerName) == false)
        {
            err("Issuer " + issuerName + " is not within the configured issuers " + issuerNames);
            return null;
        }

        EnvironmentParameterResolver environment = null;
        if(envName != null)
        {
            Set<String> envNames = qaSystemManager.getEnvironmentNames();
            if(envNames.contains(envName) == false)
            {
                err("Environment " + envName + " is not within the configured environments " + envNames);
                return null;
            } else
            {
                environment = qaSystemManager.getEnvironment(envName);
            }
        }

        X509IssuerInfo issuerInfo = qaSystemManager.getIssuer(issuerName);

        X509CertProfileQA qa = qaSystemManager.getCertprofile(profileName);
        if(qa == null)
        {
            err("Found no certificate profile named '" + profileName + "'");
            return null;
        }

        CertificationRequest p10Req = CertificationRequest.getInstance(IoUtil.read(p10File));
        Extensions extensions = null;
        ASN1Set attrs = p10Req.getCertificationRequestInfo().getAttributes();
        for(int i = 0; i < attrs.size(); i++)
        {
            Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
            if(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType()))
            {
                extensions = Extensions.getInstance(attr.getAttributeValues()[0]);
            }
        }

        byte[] certBytes = IoUtil.read(certFile);
        ValidationResult result = qa.checkCert(certBytes, issuerInfo, p10Req.getCertificationRequestInfo().getSubject(),
                p10Req.getCertificationRequestInfo().getSubjectPublicKeyInfo(), extensions, environment);
        StringBuilder sb = new StringBuilder();

        sb.append("certificate is ");
        sb.append(result.isAllSuccessful()? "valid" : "invalid");

        if(verbose.booleanValue())
        {
            for(ValidationIssue issue : result.getValidationIssues())
            {
                sb.append("\n");
                format(issue, "    ", sb);
            }

        }

        System.out.println(sb);
        return null;
    }

    public void setQaSystemManager(QASystemManager qaSystemManager)
    {
        this.qaSystemManager = qaSystemManager;
    }

    private static void format(ValidationIssue issue, String prefix, StringBuilder sb)
    {
        sb.append(prefix);
        sb.append(issue.getCode());
        sb.append(", ").append(issue.getDescription());
        sb.append(", ").append(issue.isFailed() ? "failure" : "successful");
        if(issue.getMessage() != null)
        {
            sb.append(", ").append(issue.getMessage());
        }
    }

}
