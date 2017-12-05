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
     * Returns whether include subject and serial number of the issuer certificate in the
     * AuthorityKeyIdentifier extension.
     * 
     * @return whether include subject and serial number of the issuer certificate in the
     *         AuthorityKeyIdentifier extension.
     */
    public boolean includeIssuerAndSerialInAki() {
        return false;
    }

    public AuthorityInfoAccessControl aiaControl() {
        return null;
    }

    /**
     * Increments the SerialNumber attribute in the subject
     * @param currentSerialNumber
     *          Current serial number. Could be {@code null}.
     * @return the incremented serial number
     * @throws BadFormatException
     *         If the currentSerialNumber is not a non-negative decimal long.
     */
    public String incSerialNumber(final String currentSerialNumber)
            throws BadFormatException {
        try {
            long currentSn = (currentSerialNumber == null) ? 0
                    : Long.parseLong(currentSerialNumber.trim());
            if (currentSn < 0) {
                throw new BadFormatException("invalid currentSerialNumber " + currentSerialNumber);
            }
            return Long.toString(currentSn + 1);
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
     * Returns the parameter value for the given name.
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
     * Returns the SubjectInfoAccess modes. 
     * Use the dummy oid 0.0.0.0 to identify the NULL accessMethod.
     * 
     * @return the SubjectInfoAccess modes.
     */
    public Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> subjectInfoAccessModes() {
        return null;
    }

    public abstract Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls();

    /**
     * Initializes this object.
     * 
     * @param data
     *          Configuration. Could be {@code null}.
     * @throws CertprofileException
     *         if error during the initialization occurs.
     */
    public abstract void initialize(String data) throws CertprofileException;

    public abstract X509CertLevel certLevel();

    public abstract Set<KeyUsageControl> keyUsage();

    public abstract Integer pathLenBasicConstraint();

    /**
     * Sets the {{@link EnvParameterResolver}.
     *
     * @param parameterResolver
     *          Parameter resolver. Could be {@code null}.
     */
    public abstract void setEnvParameterResolver(EnvParameterResolver parameterResolver);

    /**
     * Checks and gets the granted NotBefore.
     * 
     * @param notBefore
     *          Requested NotBefore. Could be {@code null}.
     * @return the granted NotBefore.
     */
    public abstract Date getNotBefore(Date notBefore);

    public abstract CertValidity validity();

    /**
     * Checks the public key. If the check passes, returns the canonicalized public key.
     * 
     * @param publicKey
     *          Requested public key. Must not be {@code null}.
     * @return the granted public key.
     * @throws BadCertTemplateException
     *         If the publicKey does not have correct format or is not permitted.
     */
    public abstract SubjectPublicKeyInfo checkPublicKey(SubjectPublicKeyInfo publicKey)
            throws BadCertTemplateException;

    /**
     * Checks the requested subject. If the check passes, returns the canonicalized subject.
     * 
     * @param requestedSubject
     *          Requested subject. Must not be {@code null}.
     * @return the granted subject
     * @throws BadCertTemplateException
     *         if the subject is not permitted.
     * @throws CertprofileException
     *         if error occurs.
     */
    public abstract SubjectInfo getSubject(X500Name requestedSubject)
            throws CertprofileException, BadCertTemplateException;

    /**
     * Checks the requested extensions and returns the canonicalized ones.
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
     * @throws BadCertTemplateException
     *         if at least one of extension is not permitted.
     * @throws CertprofileException
     *         if error occurs.
     */
    public abstract ExtensionValues getExtensions(
            Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls,
            X500Name requestedSubject, X500Name grantedSubject,
            Extensions requestedExtensions, Date notBefore, Date notAfter)
            throws CertprofileException, BadCertTemplateException;

    public abstract boolean incSerialNumberIfSubjectExists();

    /**
     * Returns maximal size in bytes of the certificate.
     *
     * @return maximal size in bytes of the certificate, 0 or negative value
     *         indicates accepting all sizes.
     */
    public int maxCertSize() {
        return 0;
    }

}
