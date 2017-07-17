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

package org.xipki.ca.api.profile.x509;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.BadFormatException;
import org.xipki.ca.api.EnvParameterResolver;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.ExtensionControl;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.GeneralNameMode;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class X509Certprofile {

    private TimeZone timeZone = TimeZone.getTimeZone("UTC");

    public boolean isOnlyForRa() {
        return false;
    }

    public void shutdown() {
    }

    public X509CertVersion version() {
        return X509CertVersion.v3;
    }

    public List<String> signatureAlgorithms() {
        return null;
    }

    public SpecialX509CertprofileBehavior specialCertprofileBehavior() {
        return null;
    }

    /**
     * Whether include subject and serial number of the issuer certificate in the
     * AuthorityKeyIdentifier extension.
     */
    public boolean includeIssuerAndSerialInAki() {
        return false;
    }

    public AuthorityInfoAccessControl aiaControl() {
        return null;
    }

    /**
     *
     * @param currentSerialNumber
     *          Current serial number. Could be {@code null}.
     * @return the incremented serial number
     * @throws BadFormatException
     */
    public String incSerialNumber(final String currentSerialNumber)
            throws BadFormatException {
        try {
            int currentSn = (currentSerialNumber == null) ? 0
                    : Integer.parseInt(currentSerialNumber.trim());
            return Integer.toString(currentSn + 1);
        } catch (NumberFormatException ex) {
            throw new BadFormatException(String.format(
                    "invalid serialNumber attribute %s", currentSerialNumber));
        }
    }

    public boolean isDuplicateKeyPermitted() {
        return true;
    }

    public boolean isDuplicateSubjectPermitted() {
        return true;
    }

    /**
     * Whether the subject attribute serialNumber in request is permitted.
     *
     * @return whether the serialNumber is permitted in request.
     */
    public boolean isSerialNumberInReqPermitted() {
        return true;
    }

    /**
     *
     * @param paramName
     *          Parameter name. Must not be {@code null}.
     * @return parameter value.
     */
    public String parameter(final String paramName) {
        return null;
    }

    public boolean hasMidnightNotBefore() {
        return false;
    }

    public TimeZone timezone() {
        return timeZone;
    }

    public Set<ExtKeyUsageControl> extendedKeyUsages() {
        return null;
    }

    /**
     * Use the dummy oid 0.0.0.0 to identify the NULL accessMethod.
     */
    public Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> subjectInfoAccessModes() {
        return null;
    }

    public abstract Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls();

    /**
     *
     * @param data
     *          Configuration. Could be {@code null}.
     */
    public abstract void initialize(String data) throws CertprofileException;

    public abstract X509CertLevel certLevel();

    public abstract Set<KeyUsageControl> keyUsage();

    public abstract Integer pathLenBasicConstraint();

    /**
     *
     * @param parameterResolver
     *          Parameter resolver. Could be {@code null}.
     */
    public abstract void setEnvParameterResolver(EnvParameterResolver parameterResolver);

    /**
     *
     * @param notBefore
     *          Requested NotBefore. Could be {@code null}.
     * @return the granted NotBefore.
     */
    public abstract Date getNotBefore(Date notBefore);

    public abstract CertValidity validity();

    /**
     *
     * @param publicKey
     *          Requested public key. Must not be {@code null}.
     * @return the granted public key.
     */
    public abstract SubjectPublicKeyInfo checkPublicKey(SubjectPublicKeyInfo publicKey)
            throws BadCertTemplateException;

    /**
     *
     * @param requestedSubject
     *          Requested subject. Must not be {@code null}.
     * @return the granted subject
     */
    public abstract SubjectInfo getSubject(X500Name requestedSubject)
            throws CertprofileException, BadCertTemplateException;

    /**
     *
     * @param extensionControls
     *          Extension controls. Must not be {@code null}.
     * @param requestedSubject
     *          Requested subject. Must not be {@code null}.
     * @param grantedSubject
     *          Granted subject. Must not be {@code null}.
     * @param requestedExtensions
     *          Requested extensions. Could be {@code null}.
     * @param notBefore
     *          NotBefore. Must not be {@code null}.
     * @param notAfter
     *          NotAfter. Must not be {@code null}.
     * @return extensions of the certificate to be issued.
     */
    public abstract ExtensionValues getExtensions(
            Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls,
            X500Name requestedSubject, X500Name grantedSubject,
            Extensions requestedExtensions, Date notBefore, Date notAfter)
            throws CertprofileException, BadCertTemplateException;

    public abstract boolean incSerialNumberIfSubjectExists();

    /**
     * @return maximal size of the certificate, 0 or negative value indicates accepting all sizes.
     */
    public int maxCertSize() {
        return 0;
    }

}
