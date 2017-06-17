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

package org.xipki.pki.ca.server.impl;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.pki.ca.api.NameId;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.OperationException.ErrorCode;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.server.impl.store.CertificateStore;
import org.xipki.pki.ca.server.mgmt.api.CaEntry;
import org.xipki.pki.ca.server.mgmt.api.CaStatus;
import org.xipki.pki.ca.server.mgmt.api.PermissionConstants;
import org.xipki.pki.ca.server.mgmt.api.ValidityMode;
import org.xipki.pki.ca.server.mgmt.api.x509.RevokeSuspendedCertsControl;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.exception.XiSecurityException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509CaInfo {

    private static final long MS_PER_DAY = 24L * 60 * 60 * 1000;

    private final X509CaEntry caEntry;

    private long noNewCertificateAfter;

    private BigInteger serialNumber;

    private Date notBefore;

    private Date notAfter;

    private boolean selfSigned;

    private CMPCertificate certInCmpFormat;

    private PublicCaInfo publicCaInfo;

    private CertificateStore certStore;

    private RandomSerialNumberGenerator randomSnGenerator;

    private Map<String, ConcurrentContentSigner> signers;

    private ConcurrentContentSigner dfltSigner;

    private RevokeSuspendedCertsControl revokeSuspendedCertsControl;

    public X509CaInfo(final X509CaEntry caEntry, final CertificateStore certStore)
            throws OperationException {
        this.caEntry = ParamUtil.requireNonNull("caEntry", caEntry);
        this.certStore = ParamUtil.requireNonNull("certStore", certStore);

        X509Certificate cert = caEntry.certificate();
        this.notBefore = cert.getNotBefore();
        this.notAfter = cert.getNotAfter();
        this.serialNumber = cert.getSerialNumber();
        this.selfSigned = cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());

        Certificate bcCert;
        try {
            byte[] encodedCert = cert.getEncoded();
            bcCert = Certificate.getInstance(encodedCert);
        } catch (CertificateEncodingException ex) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                    "could not encode the CA certificate");
        }
        this.certInCmpFormat = new CMPCertificate(bcCert);

        this.publicCaInfo = new PublicCaInfo(cert,
                caEntry.cacertUris(),
                caEntry.ocspUris(),
                caEntry.crlUris(),
                caEntry.deltaCrlUris());

        this.noNewCertificateAfter =
                this.notAfter.getTime() - MS_PER_DAY * caEntry.expirationPeriod();

        this.randomSnGenerator = RandomSerialNumberGenerator.getInstance();
    } // constructor

    public PublicCaInfo publicCaInfo() {
        return publicCaInfo;
    }

    public String subject() {
        return caEntry.subject();
    }

    public Date notBefore() {
        return notBefore;
    }

    public Date notAfter() {
        return notAfter;
    }

    public BigInteger serialNumber() {
        return serialNumber;
    }

    public boolean isSelfSigned() {
        return selfSigned;
    }

    public CMPCertificate certInCmpFormat() {
        return certInCmpFormat;
    }

    public long noNewCertificateAfter() {
        return noNewCertificateAfter;
    }

    public X509CaEntry caEntry() {
        return caEntry;
    }

    public NameId ident() {
        return caEntry.ident();
    }

    public List<String> crlUris() {
        return caEntry.crlUris();
    }

    public String crlUrisAsString() {
        return caEntry.crlUrisAsString();
    }

    public List<String> deltaCrlUris() {
        return caEntry.deltaCrlUris();
    }

    public String deltaCrlUrisAsString() {
        return caEntry.deltaCrlUrisAsString();
    }

    public List<String> ocspUris() {
        return caEntry.ocspUris();
    }

    public String ocspUrisAsString() {
        return caEntry.ocspUrisAsString();
    }

    public CertValidity maxValidity() {
        return caEntry.maxValidity();
    }

    public void setMaxValidity(final CertValidity maxValidity) {
        caEntry.setMaxValidity(maxValidity);
    }

    public X509Cert certificate() {
        return publicCaInfo.caCertificate();
    }

    public String signerConf() {
        return caEntry.signerConf();
    }

    public String crlSignerName() {
        return caEntry.crlSignerName();
    }

    public void setCrlSignerName(final String crlSignerName) {
        caEntry.setCrlSignerName(crlSignerName);
    }

    public String cmpControlName() {
        return caEntry.cmpControlName();
    }

    public void setCmpControlName(final String name) {
        caEntry.setCmpControlName(name);
    }

    public String responderName() {
        return caEntry.responderName();
    }

    public void setResponderName(final String name) {
        caEntry.setResponderName(name);
    }

    public int numCrls() {
        return caEntry.numCrls();
    }

    public CaStatus status() {
        return caEntry.status();
    }

    public void setStatus(final CaStatus status) {
        caEntry.setStatus(status);
    }

    public String signerType() {
        return caEntry.signerType();
    }

    @Override
    public String toString() {
        return caEntry.toString(false);
    }

    public String toString(final boolean verbose) {
        return caEntry.toString(verbose);
    }

    public boolean isDuplicateKeyPermitted() {
        return caEntry.isDuplicateKeyPermitted();
    }

    public void setDuplicateKeyPermitted(final boolean permitted) {
        caEntry.setDuplicateKeyPermitted(permitted);
    }

    public boolean isDuplicateSubjectPermitted() {
        return caEntry.isDuplicateSubjectPermitted();
    }

    public void setDuplicateSubjectPermitted(final boolean permitted) {
        caEntry.setDuplicateSubjectPermitted(permitted);
    }

    public boolean isSaveRequest() {
        return caEntry.isSaveRequest();
    }

    public void setSaveRequest(final boolean saveRequest) {
        caEntry.setSaveRequest(saveRequest);
    }

    public ValidityMode validityMode() {
        return caEntry.validityMode();
    }

    public void setValidityMode(final ValidityMode mode) {
        caEntry.setValidityMode(mode);
    }

    public int permission() {
        return caEntry.permission();
    }

    public void setPermission(final int permission) {
        caEntry.setPermission(permission);
    }

    public CertRevocationInfo revocationInfo() {
        return caEntry.revocationInfo();
    }

    public void setRevocationInfo(final CertRevocationInfo revocationInfo) {
        caEntry.setRevocationInfo(revocationInfo);
    }

    public int expirationPeriod() {
        return caEntry.expirationPeriod();
    }

    public void setKeepExpiredCertInDays(int days) {
        caEntry.setKeepExpiredCertInDays(days);
    }

    public int leepExpiredCertInDays() {
        return caEntry.keepExpiredCertInDays();
    }

    public Date crlBaseTime() {
        return caEntry.crlBaseTime();
    }

    public BigInteger nextSerial() throws OperationException {
        return randomSnGenerator.nextSerialNumber(caEntry.serialNoBitLen());
    }

    public BigInteger nextCrlNumber() throws OperationException {
        long crlNo = caEntry.nextCrlNumber();
        long currentMaxNo = certStore.getMaxCrlNumber(caEntry.ident());
        if (crlNo <= currentMaxNo) {
            crlNo = currentMaxNo + 1;
        }
        caEntry.setNextCrlNumber(crlNo + 1);
        return BigInteger.valueOf(crlNo);
    }

    public ConcurrentContentSigner getSigner(final List<String> algoNames) {
        if (CollectionUtil.isEmpty(algoNames)) {
            return dfltSigner;
        }

        for (String name : algoNames) {
            if (signers.containsKey(name)) {
                return signers.get(name);
            }
        }

        return null;
    }

    public boolean initSigner(final SecurityFactory securityFactory) throws XiSecurityException {
        if (signers != null) {
            return true;
        }
        dfltSigner = null;

        List<String[]> signerConfs = CaEntry.splitCaSignerConfs(caEntry.signerConf());

        Map<String, ConcurrentContentSigner> tmpSigners = new HashMap<>();
        for (String[] m : signerConfs) {
            String algo = m[0];
            SignerConf signerConf = new SignerConf(m[1]);
            ConcurrentContentSigner signer;
            try {
                signer = securityFactory.createSigner(caEntry.signerType(), signerConf,
                        caEntry.certificate());
                if (dfltSigner == null) {
                    dfltSigner = signer;
                }
                tmpSigners.put(algo, signer);
            } catch (Throwable th) {
                for (ConcurrentContentSigner ccs : tmpSigners.values()) {
                    ccs.shutdown();
                }
                tmpSigners.clear();
                throw new XiSecurityException("could not initialize the CA signer");
            }
        }

        this.signers = Collections.unmodifiableMap(tmpSigners);
        return true;
    } // method initSigner

    public boolean isSignerRequired() {
        int permission = caEntry.permission();
        return PermissionConstants.contains(permission, PermissionConstants.ENROLL_CROSS)
                || PermissionConstants.contains(permission, PermissionConstants.ENROLL_CERT)
                || PermissionConstants.contains(permission, PermissionConstants.GEN_CRL)
                || PermissionConstants.contains(permission, PermissionConstants.KEY_UPDATE);
    } // method isSignerRequired

    public RevokeSuspendedCertsControl revokeSuspendedCertsControl() {
        return revokeSuspendedCertsControl;
    }

    public void setRevokeSuspendedCertsControl(
            RevokeSuspendedCertsControl revokeSuspendedCertsControl) {
        this.revokeSuspendedCertsControl = revokeSuspendedCertsControl;
    }

}
