/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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

package org.xipki.ca.server.mgmt.api;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.xipki.ca.api.NameId;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.common.ConfPairs;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.CompareUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.security.SignerConf;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.AlgorithmUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaEntry {

    private NameId ident;

    private CaStatus status;

    private CertValidity maxValidity;

    private String signerType;

    private String signerConf;

    private String cmpControlName;

    private String responderName;

    private boolean duplicateKeyPermitted;

    private boolean duplicateSubjectPermitted;

    private boolean saveRequest;

    private ValidityMode validityMode = ValidityMode.STRICT;

    private int permission;

    private int expirationPeriod;

    private int keepExpiredCertInDays;

    private String extraControl;

    public CaEntry(final NameId ident, final String signerType, final String signerConf,
            final int expirationPeriod) throws CaMgmtException {
        this.ident = ParamUtil.requireNonNull("ident", ident);
        this.signerType = ParamUtil.requireNonBlank("signerType", signerType);
        this.expirationPeriod = ParamUtil.requireMin("expirationPeriod", expirationPeriod, 0);
        this.signerConf = ParamUtil.requireNonBlank("signerConf", signerConf);
    }

    public static List<String[]> splitCaSignerConfs(final String conf) throws XiSecurityException {
        ConfPairs pairs = new ConfPairs(conf);
        String str = pairs.value("algo");
        List<String> list = StringUtil.split(str, ":");
        if (list == null) {
            throw new XiSecurityException("no algo is defined in CA signerConf");
        }

        List<String[]> signerConfs = new ArrayList<>(list.size());
        for (String n : list) {
            String c14nAlgo;
            try {
                c14nAlgo = AlgorithmUtil.canonicalizeSignatureAlgo(n);
            } catch (NoSuchAlgorithmException ex) {
                throw new XiSecurityException(ex.getMessage(), ex);
            }
            pairs.putPair("algo", c14nAlgo);
            signerConfs.add(new String[]{c14nAlgo, pairs.getEncoded()});
        }

        return signerConfs;
    }

    public NameId ident() {
        return ident;
    }

    public CertValidity maxValidity() {
        return maxValidity;
    }

    public void setMaxValidity(final CertValidity maxValidity) {
        this.maxValidity = maxValidity;
    }

    public int keepExpiredCertInDays() {
        return keepExpiredCertInDays;
    }

    public void setKeepExpiredCertInDays(final int days) {
        this.keepExpiredCertInDays = days;
    }

    public String signerConf() {
        return signerConf;
    }

    public CaStatus status() {
        return status;
    }

    public void setStatus(final CaStatus status) {
        this.status = status;
    }

    public String signerType() {
        return signerType;
    }

    public void setCmpControlName(final String cmpControlName) {
        this.cmpControlName = (cmpControlName == null) ? null : cmpControlName.toUpperCase();
    }

    public String cmpControlName() {
        return cmpControlName;
    }

    public String responderName() {
        return responderName;
    }

    public void setResponderName(final String responderName) {
        this.responderName = (responderName == null) ? null : responderName.toUpperCase();
    }

    public boolean isDuplicateKeyPermitted() {
        return duplicateKeyPermitted;
    }

    public void setDuplicateKeyPermitted(final boolean duplicateKeyPermitted) {
        this.duplicateKeyPermitted = duplicateKeyPermitted;
    }

    public boolean isDuplicateSubjectPermitted() {
        return duplicateSubjectPermitted;
    }

    public void setDuplicateSubjectPermitted(final boolean duplicateSubjectPermitted) {
        this.duplicateSubjectPermitted = duplicateSubjectPermitted;
    }

    public boolean isSaveRequest() {
        return saveRequest;
    }

    public void setSaveRequest(boolean saveRequest) {
        this.saveRequest = saveRequest;
    }

    public ValidityMode validityMode() {
        return validityMode;
    }

    public void setValidityMode(final ValidityMode mode) {
        this.validityMode = ParamUtil.requireNonNull("mode", mode);
    }

    public int permission() {
        return permission;
    }

    public void setPermission(final int permission) {
        this.permission = permission;
    }

    public int expirationPeriod() {
        return expirationPeriod;
    }

    public String extraControl() {
        return extraControl;
    }

    public void setExtraControl(final String extraControl) {
        this.extraControl = extraControl;
    }

    @Override
    public String toString() {
        return toString(false);
    }

    public String toString(final boolean verbose) {
        return toString(verbose, true);
    }

    public String toString(final boolean verbose, final boolean ignoreSensitiveInfo) {
        StringBuilder sb = new StringBuilder(500);
        sb.append("id: ").append(ident.id()).append('\n');
        sb.append("name: ").append(ident.name()).append('\n');
        sb.append("status: ").append((status == null) ? "null" : status.status()).append('\n');
        sb.append("maxValidity: ").append(maxValidity).append("\n");
        sb.append("expirationPeriod: ").append(expirationPeriod).append(" days\n");
        sb.append("signerType: ").append(signerType).append('\n');
        sb.append("signerConf: ");
        if (signerConf == null) {
            sb.append("null");
        } else {
            sb.append(SignerConf.toString(signerConf, verbose, ignoreSensitiveInfo));
        }
        sb.append('\n');
        sb.append("cmpcontrolName: ").append(cmpControlName).append('\n');
        sb.append("responderName: ").append(responderName).append('\n');
        sb.append("duplicateKey: ").append(duplicateKeyPermitted).append('\n');
        sb.append("duplicateSubject: ").append(duplicateSubjectPermitted).append('\n');
        sb.append("saveRequest: ").append(saveRequest).append('\n');
        sb.append("validityMode: ").append(validityMode).append('\n');
        sb.append("permission: ").append(permission).append('\n');
        sb.append("keepExpiredCerts: ");
        if (keepExpiredCertInDays < 0) {
            sb.append("forever");
        } else {
            sb.append(keepExpiredCertInDays).append(" days");
        }
        sb.append("\n");
        sb.append("extraControl: ").append(extraControl).append('\n');

        return sb.toString();
    } // method toString

    protected static String toString(final Collection<? extends Object> tokens) {
        if (CollectionUtil.isEmpty(tokens)) {
            return null;
        }

        StringBuilder sb = new StringBuilder();

        int size = tokens.size();
        int idx = 0;
        for (Object token : tokens) {
            sb.append(token);
            if (idx++ < size - 1) {
                sb.append(", ");
            }
        }
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof CaEntry)) {
            return false;
        }

        CaEntry objB = (CaEntry) obj;
        if (!ident.equals(objB.ident)) {
            return false;
        }

        if (!signerType.equals(objB.signerType)) {
            return false;
        }

        if (!CompareUtil.equalsObject(status, objB.status)) {
            return false;
        }

        if (!CompareUtil.equalsObject(maxValidity, objB.maxValidity)) {
            return false;
        }

        if (!CompareUtil.equalsObject(cmpControlName, objB.cmpControlName)) {
            return false;
        }

        if (!CompareUtil.equalsObject(responderName, objB.responderName)) {
            return false;
        }

        if (duplicateKeyPermitted != objB.duplicateKeyPermitted) {
            return false;
        }

        if (duplicateSubjectPermitted != objB.duplicateSubjectPermitted) {
            return false;
        }

        if (saveRequest != objB.saveRequest) {
            return false;
        }

        if (!CompareUtil.equalsObject(validityMode, objB.validityMode)) {
            return false;
        }

        if (permission != objB.permission) {
            return false;
        }

        if (expirationPeriod != objB.expirationPeriod) {
            return false;
        }

        if (keepExpiredCertInDays != objB.keepExpiredCertInDays) {
            return false;
        }

        if (!CompareUtil.equalsObject(extraControl, objB.extraControl)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return ident.hashCode();
    }

}
