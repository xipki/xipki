/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.server.mgmt.qa.shell.cert;

import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extensions;
import org.xipki.ca.qa.QaSystemManager;
import org.xipki.ca.qa.X509CertprofileQa;
import org.xipki.ca.qa.X509IssuerInfo;
import org.xipki.ca.server.mgmt.qa.shell.completer.X509CertprofileNameCompleter;
import org.xipki.ca.server.mgmt.qa.shell.completer.X509IssuerNameCompleter;
import org.xipki.common.qa.ValidationIssue;
import org.xipki.common.qa.ValidationResult;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.XiAction;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "caqa", name = "check-cert",
        description = "check the certificate")
@Service
public class CheckCertCmd extends XiAction {

    @Option(name = "--cert", aliases = "-c",
            required = true,
            description = "certificate file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Option(name = "--issuer",
            description = "issuer name\n"
                    + "required if multiple issuers are configured")
    @Completion(X509IssuerNameCompleter.class)
    private String issuerName;

    @Option(name = "--csr",
            required = true,
            description = "CSR file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String csrFile;

    @Option(name = "--profile", aliases = "-p",
            required = true,
            description = "certificate profile\n"
                    + "(required)")
    @Completion(X509CertprofileNameCompleter.class)
    private String profileName;

    @Option(name = "--verbose", aliases = "-v",
            description = "show status verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Reference
    private QaSystemManager qaSystemManager;

    @Override
    protected Object execute0() throws Exception {
        Set<String> issuerNames = qaSystemManager.issuerNames();
        if (isEmpty(issuerNames)) {
            throw new IllegalCmdParamException("no issuer is configured");
        }

        if (issuerName == null) {
            if (issuerNames.size() != 1) {
                throw new IllegalCmdParamException("no issuer is specified");
            }

            issuerName = issuerNames.iterator().next();
        }

        if (!issuerNames.contains(issuerName)) {
            throw new IllegalCmdParamException("issuer " + issuerName
                    + " is not within the configured issuers " + issuerNames);
        }

        X509IssuerInfo issuerInfo = qaSystemManager.getIssuer(issuerName);

        X509CertprofileQa qa = qaSystemManager.getCertprofile(profileName);
        if (qa == null) {
            throw new IllegalCmdParamException("found no certificate profile named '"
                    + profileName + "'");
        }

        CertificationRequest csr = CertificationRequest.getInstance(IoUtil.read(csrFile));
        Extensions extensions = null;
        CertificationRequestInfo reqInfo = csr.getCertificationRequestInfo();
        ASN1Set attrs = reqInfo.getAttributes();
        for (int i = 0; i < attrs.size(); i++) {
            Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
            if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType())) {
                extensions = Extensions.getInstance(attr.getAttributeValues()[0]);
            }
        }

        byte[] certBytes = IoUtil.read(certFile);
        ValidationResult result = qa.checkCert(certBytes, issuerInfo, reqInfo.getSubject(),
                reqInfo.getSubjectPublicKeyInfo(), extensions);
        StringBuilder sb = new StringBuilder();

        sb.append(certFile).append(" (certprofile ").append(profileName).append(")\n");
        sb.append("\tcertificate is ");
        sb.append(result.isAllSuccessful() ? "valid" : "invalid");

        if (verbose.booleanValue()) {
            for (ValidationIssue issue : result.validationIssues()) {
                sb.append("\n");
                format(issue, "    ", sb);
            }
        }

        println(sb.toString());
        if (!result.isAllSuccessful()) {
            throw new CmdFailure("certificate is invalid");
        }
        return null;
    } // method execute0

    private static void format(final ValidationIssue issue, final String prefix,
            final StringBuilder sb) {
        sb.append(prefix).append(issue.code());
        sb.append(", ").append(issue.description());
        sb.append(", ").append(issue.isFailed() ? "failed" : "successful");
        if (issue.failureMessage() != null) {
            sb.append(", ").append(issue.failureMessage());
        }
    }

}
