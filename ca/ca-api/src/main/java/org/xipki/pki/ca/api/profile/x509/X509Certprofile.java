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

package org.xipki.pki.ca.api.profile.x509;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.pki.ca.api.BadCertTemplateException;
import org.xipki.pki.ca.api.BadFormatException;
import org.xipki.pki.ca.api.EnvParameterResolver;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.api.profile.CertprofileException;
import org.xipki.pki.ca.api.profile.ExtensionControl;
import org.xipki.pki.ca.api.profile.ExtensionValues;
import org.xipki.pki.ca.api.profile.GeneralNameMode;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class X509Certprofile {

    public static final ASN1ObjectIdentifier OID_ZERO = new ASN1ObjectIdentifier("0.0.0.0");

    private TimeZone timeZone = TimeZone.getTimeZone("UTC");

    public boolean isOnlyForRa() {
        return false;
    }

    public void shutdown() {
    }

    public X509CertVersion getVersion() {
        return X509CertVersion.v3;
    }

    public List<String> getSignatureAlgorithms() {
        return null;
    }

    public SpecialX509CertprofileBehavior getSpecialCertprofileBehavior() {
        return null;
    }

    /**
     * Whether include subject and serial number of the issuer certificate in the
     * AuthorityKeyIdentifier extension.
     */
    public boolean includeIssuerAndSerialInAki() {
        return false;
    }

    public AuthorityInfoAccessControl getAiaControl() {
        return null;
    }

    public String incSerialNumber(
            @Nullable final String currentSerialNumber)
    throws BadFormatException {
        try {
            int currentSn = (currentSerialNumber == null)
                    ? 0
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

    public String getParameter(
            @Nonnull final String paramName) {
        return null;
    }

    public boolean hasMidnightNotBefore() {
        return false;
    }

    public TimeZone getTimezone() {
        return timeZone;
    }

    public Set<ExtKeyUsageControl> getExtendedKeyUsages() {
        return null;
    }

    public Set<GeneralNameMode> getSubjectAltNameModes() {
        return null;
    }

    /**
     * Use the dummy oid 0.0.0.0 to identify the NULL accessMethod.
     */
    public Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> getSubjectInfoAccessModes() {
        return null;
    }

    public abstract Map<ASN1ObjectIdentifier, ExtensionControl> getExtensionControls();

    public abstract void initialize(
            @Nullable String data)
    throws CertprofileException;

    public abstract X509CertLevel getCertLevel();

    public abstract Set<KeyUsageControl> getKeyUsage();

    public abstract Integer getPathLenBasicConstraint();

    public abstract void setEnvParameterResolver(
            @Nullable EnvParameterResolver parameterResolver);

    public abstract Date getNotBefore(
            @Nullable Date notBefore);

    public abstract CertValidity getValidity();

    public abstract SubjectPublicKeyInfo checkPublicKey(
            @Nonnull SubjectPublicKeyInfo publicKey)
    throws BadCertTemplateException;

    public abstract SubjectInfo getSubject(
            @Nonnull X500Name requestedSubject)
    throws CertprofileException, BadCertTemplateException;

    public abstract ExtensionValues getExtensions(
            @Nonnull Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls,
            @Nonnull X500Name requestedSubject,
            @Nullable Extensions requestExtensions,
            @Nonnull Date notBefore,
            @Nonnull Date notAfter)
    throws CertprofileException, BadCertTemplateException;

    public abstract boolean incSerialNumberIfSubjectExists();

    /**
     * @return maximal size of the certificate, 0 or negative value indicates accepting all sizes.
     */
    public int getMaxCertSize() {
        return 0;
    }

}
