/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

import java.io.FileInputStream;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.util.encoders.Base64;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.commons.password.api.PasswordResolver;
import org.xipki.commons.security.api.CertRevocationInfo;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.server.mgmt.api.CaStatus;
import org.xipki.pki.ca.server.mgmt.api.CertArt;
import org.xipki.pki.ca.server.mgmt.api.Permission;
import org.xipki.pki.ca.server.mgmt.api.ValidityMode;
import org.xipki.pki.ca.server.mgmt.api.X509CaEntry;
import org.xipki.pki.ca.server.mgmt.api.X509CaUris;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-ca", name = "ca-addf",
        description = "add CA from configuration file")
@Service
public class CaAddFromFileCmd extends CaCommandSupport {

    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "CA name\n"
                    + "(required)")
    private String caName;

    @Option(name = "--conf-file",
            required = true,
            description = "CA configuration file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String confFile;

    @Reference
    private PasswordResolver passwordResolver;

    @Override
    protected Object doExecute()
    throws Exception {
        X509CaEntry caEntry = getCaEntry(false);

        boolean bo = caManager.addCa(caEntry);
        output(bo, "added", "could not add", "CA " + caEntry.getName());
        return null;
    }

    protected X509CaEntry getCaEntry(
            final boolean ignoreCert)
    throws Exception {
        Properties props = new Properties();
        confFile = IoUtil.expandFilepath(confFile);
        FileInputStream stream = new FileInputStream(confFile);
        try {
            props.load(stream);
        } finally {
            stream.close();
        }

        // ART
        String key = CaExportCmd.KEY_ART;
        String str = getStrProp(props, key, true);
        CertArt art = CertArt.valueOf(str);
        assertNotNull(art, key, str);

        if (art != CertArt.X509PKC) {
            throw new IllegalCmdParamException("unsupported " + key + ": '" + str + "'");
        }

        // NEXT_SN
        key = CaExportCmd.KEY_NEXT_SN;
        long nextSerial = getRequiredLongProp(props, key);
        if (nextSerial < 0) {
            throw new IllegalCmdParamException("invalid " + key + ": " + nextSerial);
        }

        // NEXT_CRLNO
        key = CaExportCmd.KEY_NEXT_CRLNO;
        int nextCrlNumber = getRequiredIntProp(props, key);
        if (nextCrlNumber < 1) {
            throw new IllegalCmdParamException("invalid " + key + ": " + nextCrlNumber);
        }

        // NUM_CRLS
        key = CaExportCmd.KEY_NUM_CRLS;
        int numCrls = getRequiredIntProp(props, key);
        if (numCrls < 0) {
            throw new IllegalCmdParamException("invalid " + key + ": " + numCrls);
        }

        // EXPIRATION_PERIOD
        key = CaExportCmd.KEY_EXPIRATION_PERIOD;
        int expirationPeriod = getRequiredIntProp(props, key);
        if (expirationPeriod < 0) {
            throw new IllegalCmdParamException("invalid " + key + ": " + expirationPeriod);
        }

        // SIGNER_TYPE
        key = CaExportCmd.KEY_SIGNER_TYPE;
        String signerType = getStrProp(props, key, true);

        // SIGNER_CONF
        key = CaExportCmd.KEY_SIGNER_CONF;
        String signerConf = getStrProp(props, key, true);

        if ("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType)) {
            signerConf = ShellUtil.canonicalizeSignerConf(signerType, signerConf,
                    passwordResolver, securityFactory);
        }

        // CRL_URIS
        key = CaExportCmd.KEY_CRL_URIS;
        str = getStrProp(props, key, false);
        List<String> crlUris = null;
        if (str != null) {
            crlUris = StringUtil.split(str, ", ");
        }

        // DELTACRL_URIS
        key = CaExportCmd.KEY_DELTACRL_URIS;
        str = getStrProp(props, key, false);
        List<String> deltaCrlUris = null;
        if (str != null) {
            deltaCrlUris = StringUtil.split(str, ", ");
        }

        // OCSP_URIS
        key = CaExportCmd.KEY_OCSP_URIS;
        str = getStrProp(props, key, false);
        List<String> ocspUris = null;
        if (str != null) {
            ocspUris = StringUtil.split(str, ", ");
        }

        // CACERT_URIS
        key = CaExportCmd.KEY_CACERT_URIS;
        str = getStrProp(props, key, false);
        List<String> caCertUris = null;
        if (str != null) {
            ocspUris = StringUtil.split(str, ", ");
        }

        X509CaUris caUris = new X509CaUris(caCertUris, ocspUris, crlUris, deltaCrlUris);
        // CHECKSTYLE:SKIP
        X509CaEntry entry = new X509CaEntry(
                caName, nextSerial, nextCrlNumber, signerType, signerConf,
                caUris, numCrls, expirationPeriod);

        // STATUS
        key = CaExportCmd.KEY_STATUS;
        str = getStrProp(props, key, true);
        CaStatus status = CaStatus.getCaStatus(str);
        assertNotNull(status, key, str);
        entry.setStatus(status);

        // DUPLICATE_KEY
        key = CaExportCmd.KEY_DUPLICATE_KEY;
        str = getStrProp(props, key, true);
        entry.setDuplicateKeyPermitted(Boolean.parseBoolean(str));

        // DUPLICATE_SUBJECT
        key = CaExportCmd.KEY_DUPLICATE_SUBJECT;
        str = getStrProp(props, key, true);
        entry.setDuplicateSubjectPermitted(Boolean.parseBoolean(str));

        // VALIDITY_MODE
        key = CaExportCmd.KEY_VALIDITY_MODE;
        str = getStrProp(props, key, true);
        ValidityMode validityMode = ValidityMode.valueOf(str);
        assertNotNull(validityMode, key, str);
        entry.setValidityMode(validityMode);

        // CRLSIGNER_NAME
        key = CaExportCmd.KEY_CRLSIGNER_NAME;
        str = getStrProp(props, key, false);
        if (str != null) {
            entry.setCrlSignerName(str);
        }

        // CMPCONTROL_NAME
        key = CaExportCmd.KEY_CMPCONTROL_NAME;
        str = getStrProp(props, key, false);
        if (str != null) {
            entry.setCmpControlName(str);
        }

        // MAX_VALIDITY
        key = CaExportCmd.KEY_MAX_VALIDITY;
        str = getStrProp(props, key, true);
        CertValidity maxValidity = CertValidity.getInstance(str);
        entry.setMaxValidity(maxValidity);

        // KEEP_EXPIRED_CERT_DAYS
        key = CaExportCmd.KEY_KEEP_EXPIRED_CERT_DAYS;
        int keepExpiredCertInDays = getIntProp(props, key, true);
        entry.setKeepExpiredCertInDays(keepExpiredCertInDays);

        // EXTRA_CONTROL
        key = CaExportCmd.KEY_EXTRA_CONTROL;
        str = getStrProp(props, key, false);
        if (str != null) {
            entry.setExtraControl(str);
        }

        // PERMISSIONS
        key = CaExportCmd.KEY_PERMISSIONS;
        str = getStrProp(props, key, true);
        Set<String> permissions = StringUtil.splitAsSet(str, ", ");
        Set<Permission> tmpPermissions = new HashSet<>();
        for (String permission : permissions) {
            Permission tmpPermission = Permission.getPermission(permission);
            if (tmpPermission == null) {
                throw new IllegalCmdParamException("invalid permission: " + permission);
            }
            tmpPermissions.add(tmpPermission);
        }
        entry.setPermissions(tmpPermissions);

        // REVOKED
        key = CaExportCmd.KEY_REVOKED;
        str = getStrProp(props, key, true);
        boolean revoked;
        if ("true".equalsIgnoreCase(str) || "yes".equalsIgnoreCase(str)) {
            revoked = true;
        } else if ("false".equalsIgnoreCase(str) || "no".equalsIgnoreCase(str)) {
            revoked = false;
        } else {
            throw new IllegalCmdParamException("invalid " + key + ": '" + str + "'");
        }

        if (revoked) {
            // REV_REASON
            key = CaExportCmd.KEY_REV_REASON;
            // CHECKSTYLE:SKIP
            int reasonCode = getRequiredIntProp(props, key);

            // REV_TIME
            key = CaExportCmd.KEY_REV_TIME;
            Date revocationTime = new Date(getRequiredLongProp(props, key) * 1000);

            // REV_INV_TIME
            key = CaExportCmd.KEY_REV_INV_TIME;
            Long longValue = getLongProp(props, key, false);
            Date invalidityTime = null;
            if (longValue != null) {
                invalidityTime = new Date(longValue.longValue() * 1000);
            }
            CertRevocationInfo revInfo = new CertRevocationInfo(
                    reasonCode, revocationTime, invalidityTime);
            entry.setRevocationInfo(revInfo);
        }

        // CERT
        if (!ignoreCert) {
            key = CaExportCmd.KEY_CERT;
            str = getStrProp(props, key, false);
            byte[] certBytes = null;
            if (str != null) {
                if (StringUtil.startsWithIgnoreCase(str, "file:")) {
                    certBytes = IoUtil.read(str.substring("file:".length()));
                } else {
                    certBytes = Base64.decode(str);
                }
            }

            X509Certificate caCert = null;
            if (certBytes != null) {
                caCert = X509Util.parseCert(certBytes);
            }
            entry.setCertificate(caCert);
        }

        return entry;
    } // method getCaEntry

    private String getStrProp(
            final Properties props,
            final String propKey,
            final boolean required)
    throws IllegalCmdParamException {
        String str = props.getProperty(propKey);
        if (StringUtil.isBlank(str)) {
            str = "";
        } else {
            str = str.trim();
        }

        if (!str.isEmpty()) {
            return str;
        }

        if (required) {
            throw new IllegalCmdParamException(
                    "Required property '" + propKey + "' is not defined");
        } else {
            return null;
        }
    }

    private int getRequiredIntProp(
            final Properties props,
            final String propKey)
    throws IllegalCmdParamException {
        return getIntProp(props, propKey, true).intValue();
    }

    private Integer getIntProp(
            final Properties props,
            final String propKey,
            final boolean required)
    throws IllegalCmdParamException {
        String str = getStrProp(props, propKey, required);
        return (str == null)
                ? null
                : Integer.parseInt(str);
    }

    private long getRequiredLongProp(
            final Properties props,
            final String propKey)
    throws IllegalCmdParamException {
        return getLongProp(props, propKey, true).longValue();
    }

    private Long getLongProp(
            final Properties props,
            final String propKey,
            final boolean required)
    throws IllegalCmdParamException {
        String str = getStrProp(props, propKey, required);
        return (str == null)
                ? null
                : Long.parseLong(str);
    }

    private static void assertNotNull(
            final Object obj,
            final String key,
            final String value)
    throws IllegalCmdParamException {
        if (obj == null) {
            throw new IllegalCmdParamException("invalid " + key + ": '" + value + "'");
        }
    }

}
