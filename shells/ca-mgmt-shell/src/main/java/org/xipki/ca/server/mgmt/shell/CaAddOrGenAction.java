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

package org.xipki.ca.server.mgmt.shell;

import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.server.mgmt.api.CaStatus;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.ca.server.mgmt.api.x509.X509CaUris;
import org.xipki.ca.server.mgmt.shell.completer.CaStatusCompleter;
import org.xipki.ca.server.mgmt.shell.completer.CmpControlNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.CrlSignerNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.PermissionCompleter;
import org.xipki.ca.server.mgmt.shell.completer.ResponderNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.ValidityModeCompleter;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.completer.SignerTypeCompleter;
import org.xipki.console.karaf.completer.YesNoCompleter;
import org.xipki.password.PasswordResolver;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class CaAddOrGenAction extends CaAction {

    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "CA name\n"
                    + "(required)")
    private String caName;

    @Option(name = "--status",
            description = "CA status")
    @Completion(CaStatusCompleter.class)
    private String caStatus = "active";

    @Option(name = "--ca-cert-uri",
            multiValued = true,
            description = "CA certificate URI\n"
                    + "(multi-valued)")
    private List<String> caCertUris;

    @Option(name = "--ocsp-uri",
            multiValued = true,
            description = "OCSP URI\n"
                    + "(multi-valued)")
    private List<String> ocspUris;

    @Option(name = "--crl-uri",
            multiValued = true,
            description = "CRL distribution point\n"
                    + "(multi-valued)")
    private List<String> crlUris;

    @Option(name = "--deltacrl-uri",
            multiValued = true,
            description = "CRL distribution point\n"
                    + "(multi-valued)")
    private List<String> deltaCrlUris;

    @Option(name = "--permission",
            required = true, multiValued = true,
            description = "permission\n"
                    + "(required, multi-valued)")
    @Completion(PermissionCompleter.class)
    private Set<String> permissions;

    @Option(name = "--sn-bitlen",
            description = "number of bits of the serial number, between 63 and 159")
    private int snBitLen = 127;

    @Option(name = "--next-crl-no",
            required = true,
            description = "CRL number for the next CRL\n"
                    + "(required)")
    private Long nextCrlNumber;

    @Option(name = "--max-validity",
            required = true,
            description = "maximal validity\n"
                    + "(required)")
    private String maxValidity;

    @Option(name = "--keep-expired-certs",
            description = "days to keep expired certificates")
    private Integer keepExpiredCertInDays = -1;

    @Option(name = "--crl-signer",
            description = "CRL signer name")
    @Completion(CrlSignerNameCompleter.class)
    private String crlSignerName;

    @Option(name = "--responder",
            description = "Responder name")
    @Completion(ResponderNameCompleter.class)
    private String responderName;

    @Option(name = "--cmp-control",
            description = "CMP control name")
    @Completion(CmpControlNameCompleter.class)
    private String cmpControlName;

    @Option(name = "--num-crls",
            description = "number of CRLs to be kept in database")
    private Integer numCrls = 30;

    @Option(name = "--expiration-period",
            description = "days before expiration time of CA to issue certificates")
    private Integer expirationPeriod = 365;

    @Option(name = "--signer-type",
            required = true,
            description = "CA signer type\n"
                    + "(required)")
    @Completion(SignerTypeCompleter.class)
    private String signerType;

    @Option(name = "--signer-conf",
            required = true,
            description = "CA signer configuration")
    private String signerConf;

    @Option(name = "--duplicate-key",
            description = "whether duplicate key is permitted")
    @Completion(YesNoCompleter.class)
    private String duplicateKeyS = "yes";

    @Option(name = "--duplicate-subject",
            description = "whether duplicate subject is permitted")
    @Completion(YesNoCompleter.class)
    private String duplicateSubjectS = "yes";

    @Option(name = "--save-req",
            description = "whether the request is saved")
    @Completion(YesNoCompleter.class)
    private String saveReqS = "no";

    @Option(name = "--validity-mode",
            description = "mode of valditity")
    @Completion(ValidityModeCompleter.class)
    private String validityModeS = "STRICT";

    @Option(name = "--extra-control",
            description = "extra control")
    private String extraControl;

    @Reference
    private PasswordResolver passwordResolver;

    protected X509CaEntry getCaEntry() throws Exception {
        ParamUtil.requireRange("sn-bitlen", snBitLen, 63, 159);

        if (nextCrlNumber < 1) {
            throw new IllegalCmdParamException("invalid CRL number: " + nextCrlNumber);
        }

        if (numCrls < 0) {
            throw new IllegalCmdParamException("invalid numCrls: " + numCrls);
        }

        if (expirationPeriod < 0) {
            throw new IllegalCmdParamException("invalid expirationPeriod: " + expirationPeriod);
        }

        if ("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType)) {
            signerConf = ShellUtil.canonicalizeSignerConf(signerType, signerConf, passwordResolver,
                    securityFactory);
        }

        X509CaUris caUris = new X509CaUris(caCertUris, ocspUris, crlUris, deltaCrlUris);
        X509CaEntry entry = new X509CaEntry(new NameId(null, caName), snBitLen, nextCrlNumber,
                signerType, signerConf, caUris, numCrls.intValue(), expirationPeriod.intValue());

        entry.setKeepExpiredCertInDays(keepExpiredCertInDays.intValue());

        boolean duplicateKeyPermitted = isEnabled(duplicateKeyS, true, "duplicate-key");
        entry.setDuplicateKeyPermitted(duplicateKeyPermitted);

        boolean duplicateSubjectPermitted = isEnabled(duplicateSubjectS, true, "duplicate-subject");
        entry.setDuplicateSubjectPermitted(duplicateSubjectPermitted);

        boolean saveReq = isEnabled(saveReqS, false, "save-req");
        entry.setSaveRequest(saveReq);

        ValidityMode validityMode = ValidityMode.forName(validityModeS);
        entry.setValidityMode(validityMode);

        CaStatus status = CaStatus.forName(caStatus);
        entry.setStatus(status);
        if (crlSignerName != null) {
            entry.setCrlSignerName(crlSignerName);
        }

        if (responderName != null) {
            entry.setResponderName(responderName);
        }

        CertValidity tmpMaxValidity = CertValidity.getInstance(maxValidity);
        entry.setMaxValidity(tmpMaxValidity);

        entry.setKeepExpiredCertInDays(keepExpiredCertInDays);

        if (cmpControlName != null) {
            entry.setCmpControlName(cmpControlName);
        }

        int intPermission = ShellUtil.getPermission(permissions);
        entry.setPermission(intPermission);

        if (StringUtil.isNotBlank(extraControl)) {
            entry.setExtraControl(extraControl.trim());
        }
        return entry;
    } // method getCaEntry

}
