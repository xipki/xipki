/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.pki.ca.server.mgmt.shell;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.console.karaf.completer.SignerTypeCompleter;
import org.xipki.commons.password.api.PasswordResolver;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.server.mgmt.api.CaStatus;
import org.xipki.pki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.pki.ca.server.mgmt.api.Permission;
import org.xipki.pki.ca.server.mgmt.api.ValidityMode;
import org.xipki.pki.ca.server.mgmt.api.X509CaEntry;
import org.xipki.pki.ca.server.mgmt.api.X509CaUris;
import org.xipki.pki.ca.server.mgmt.shell.completer.CaStatusCompleter;
import org.xipki.pki.ca.server.mgmt.shell.completer.CmpControlNameCompleter;
import org.xipki.pki.ca.server.mgmt.shell.completer.CrlSignerNameCompleter;
import org.xipki.pki.ca.server.mgmt.shell.completer.DuplicationModeCompleter;
import org.xipki.pki.ca.server.mgmt.shell.completer.PermissionCompleter;
import org.xipki.pki.ca.server.mgmt.shell.completer.ResponderNameCompleter;
import org.xipki.pki.ca.server.mgmt.shell.completer.ValidityModeCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class CaAddOrGenCommandSupport extends CaCommandSupport {

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

    @Option(name = "--next-serial",
            required = true,
            description = "serial number for the next certificate, 0 for random serial number\n"
                    + "(required)")
    private Long nextSerial;

    @Option(name = "--next-crl-no",
            required = true,
            description = "CRL number for the next CRL\n"
                    + "(required)")
    private Integer nextCrlNumber;

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
            description = "CA signer configuration")
    private String signerConf;

    @Option(name = "--duplicate-key",
            description = "mode of duplicate key")
    @Completion(DuplicationModeCompleter.class)
    private String duplicateKeyS = "permitted";

    @Option(name = "--duplicate-subject",
            description = "mode of duplicate subject")
    @Completion(DuplicationModeCompleter.class)
    private String duplicateSubjectS = "permitted";

    @Option(name = "--validity-mode",
            description = "mode of valditity")
    @Completion(ValidityModeCompleter.class)
    private String validityModeS = "STRICT";

    @Option(name = "--extra-control",
            description = "extra control")
    private String extraControl;

    @Reference
    private PasswordResolver passwordResolver;

    protected X509CaEntry getCAEntry()
    throws Exception {
        if (nextSerial < 0) {
            throw new IllegalCmdParamException("invalid serial number: " + nextSerial);
        }

        if (nextCrlNumber < 1) {
            throw new IllegalCmdParamException("invalid CRL number: " + nextCrlNumber);
        }

        if (numCrls < 0) {
            throw new IllegalCmdParamException("invalid numCrls: " + numCrls);
        }

        if (expirationPeriod < 0) {
            throw new IllegalCmdParamException("invalid expirationPeriod: " + expirationPeriod);
        }

        CaStatus status = CaStatus.getCAStatus(caStatus);
        if (status == null) {
            throw new IllegalCmdParamException("invalid status: " + caStatus);
        }

        if ("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType)) {
            signerConf = ShellUtil.canonicalizeSignerConf(signerType, signerConf,
                    passwordResolver);
        }

        X509CaUris caUris = new X509CaUris(caCertUris, ocspUris, crlUris, deltaCrlUris);
        X509CaEntry entry = new X509CaEntry(
                caName, nextSerial, nextCrlNumber, signerType, signerConf,
                caUris, numCrls.intValue(), expirationPeriod.intValue());

        entry.setKeepExpiredCertInDays(keepExpiredCertInDays.intValue());

        DuplicationMode duplicateKey = DuplicationMode.getInstance(duplicateKeyS);
        if (duplicateKey == null) {
            throw new IllegalCmdParamException("invalid duplication mode: " + duplicateKeyS);
        }
        entry.setDuplicateKeyMode(duplicateKey);

        DuplicationMode duplicateSubject = DuplicationMode.getInstance(duplicateSubjectS);
        if (duplicateSubject == null) {
            throw new IllegalCmdParamException("invalid duplication mode: " + duplicateSubjectS);
        }
        entry.setDuplicateSubjectMode(duplicateSubject);

        ValidityMode validityMode = ValidityMode.getInstance(validityModeS);
        if (validityMode == null) {
            throw new IllegalCmdParamException("invalid validity: " + validityModeS);
        }
        entry.setValidityMode(validityMode);

        entry.setStatus(status);
        if (crlSignerName != null) {
            entry.setCrlSignerName(crlSignerName);
        }

        if (responderName != null) {
            entry.setResponderName(responderName);
        }

        CertValidity localMaxValidity = CertValidity.getInstance(maxValidity);
        entry.setMaxValidity(localMaxValidity);

        entry.setKeepExpiredCertInDays(keepExpiredCertInDays);

        if (cmpControlName != null) {
            entry.setCmpControlName(cmpControlName);
        }

        Set<Permission> localPermissions = new HashSet<>();
        for (String permission : permissions) {
            Permission localPermission = Permission.getPermission(permission);
            if (localPermission == null) {
                throw new IllegalCmdParamException("invalid permission: " + permission);
            }
            localPermissions.add(localPermission);
        }

        entry.setPermissions(localPermissions);

        if (StringUtil.isNotBlank(extraControl)) {
            entry.setExtraControl(extraControl.trim());
        }
        return entry;
    } // method getCAEntry

}
