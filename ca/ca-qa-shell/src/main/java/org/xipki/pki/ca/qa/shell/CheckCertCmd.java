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

package org.xipki.pki.ca.qa.shell;

import java.util.Set;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extensions;
import org.xipki.pki.ca.qa.api.QASystemManager;
import org.xipki.pki.ca.qa.api.X509CertprofileQA;
import org.xipki.pki.ca.qa.api.X509IssuerInfo;
import org.xipki.common.qa.ValidationIssue;
import org.xipki.common.qa.ValidationResult;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.XipkiOsgiCommandSupport;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-qa", name = "check-cert",
        description="check the certificate")
public class CheckCertCmd extends XipkiOsgiCommandSupport
{
    @Option(name = "--cert", aliases = "-c",
            required = true,
            description = "certificate file\n"
                    + "(required)")
    private String certFile;

    @Option(name = "--issuer",
            description = "issuer name\n"
                    + "required if multiple issuers are configured")
    private String issuerName;

    @Option(name = "--p10",
            required = true,
            description = "PKCS#10 request file\n"
                    + "(required)")
    private String p10File;

    @Option(name = "--profile", aliases = "-p",
            required = true,
            description = "certificate profile\n"
                    + "(required)")
    private String profileName;

    @Option(name = "--verbose", aliases="-v",
            description = "show status verbosely")
    private Boolean verbose = Boolean.FALSE;

    private QASystemManager qaSystemManager;

    @Override
    protected Object _doExecute()
    throws Exception
    {
        Set<String> issuerNames = qaSystemManager.getIssuerNames();
        if(isEmpty(issuerNames))
        {
            throw new IllegalCmdParamException("no issuer is configured");
        }

        if(issuerName == null)
        {
            if(issuerNames.size() != 1)
            {
                throw new IllegalCmdParamException("no issuer is specified");
            }

            issuerName = issuerNames.iterator().next();
        }

        if(issuerNames.contains(issuerName) == false)
        {
            throw new IllegalCmdParamException("issuer " + issuerName
                    + " is not within the configured issuers " + issuerNames);
        }

        X509IssuerInfo issuerInfo = qaSystemManager.getIssuer(issuerName);

        X509CertprofileQA qa = qaSystemManager.getCertprofile(profileName);
        if(qa == null)
        {
            throw new IllegalCmdParamException("found no certificate profile named '"
                    + profileName + "'");
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
        ValidationResult result = qa.checkCert(certBytes, issuerInfo,
                p10Req.getCertificationRequestInfo().getSubject(),
                p10Req.getCertificationRequestInfo().getSubjectPublicKeyInfo(), extensions);
        StringBuilder sb = new StringBuilder();

        sb.append(certFile).append(" (certprofile ").append(profileName).append(")\n");
        sb.append("\tcertificate is ");
        sb.append(result.isAllSuccessful()
                ? "valid"
                : "invalid");

        if(verbose.booleanValue())
        {
            for(ValidationIssue issue : result.getValidationIssues())
            {
                sb.append("\n");
                format(issue, "    ", sb);
            }
        }

        out(sb.toString());
        if(result.isAllSuccessful() == false)
        {
            throw new CmdFailure("certificate is invalid");
        }
        return null;
    }

    public void setQaSystemManager(QASystemManager qaSystemManager)
    {
        this.qaSystemManager = qaSystemManager;
    }

    private static void format(
            final ValidationIssue issue,
            final String prefix,
            final StringBuilder sb)
    {
        sb.append(prefix);
        sb.append(issue.getCode());
        sb.append(", ").append(issue.getDescription());
        sb.append(", ").append(
                issue.isFailed()
                    ? "failed"
                    : "successful");
        if(issue.getMessage() != null)
        {
            sb.append(", ").append(issue.getMessage());
        }
    }

}
