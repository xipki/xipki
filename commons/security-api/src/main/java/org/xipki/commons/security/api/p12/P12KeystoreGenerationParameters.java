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

package org.xipki.commons.security.api.p12;

import java.security.SecureRandom;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.KeyUsage;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P12KeystoreGenerationParameters {

    private final char[] password;

    private final X500Name subject;

    private SecureRandom random;

    private int serialNumber = 1;

    private int validity = 3650;

    private Set<KeyUsage> keyUsage;

    private List<ASN1ObjectIdentifier> extendedKeyUsage;

    public P12KeystoreGenerationParameters(
            final char[] password,
            final String subject) {
        ParamUtil.assertNotNull("password", password);
        ParamUtil.assertNotBlank("subject", subject);

        this.password = password;
        this.subject = new X500Name(subject);
    }

    public SecureRandom getRandom() {
        return random;
    }

    public void setRandom(
            final SecureRandom random) {
        this.random = random;
    }

    public char[] getPassword() {
        return password;
    }

    public X500Name getSubject() {
        return subject;
    }

    public int getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(
            final int serialNumber) {
        this.serialNumber = serialNumber;
    }

    public int getValidity() {
        return validity;
    }

    public void setValidity(
            final int validity) {
        this.validity = validity;
    }

    public Set<KeyUsage> getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(
            final Set<KeyUsage> keyUsage) {
        this.keyUsage = keyUsage;
    }

    public List<ASN1ObjectIdentifier> getExtendedKeyUsage() {
        return extendedKeyUsage;
    }

    public void setExtendedKeyUsage(
            final List<ASN1ObjectIdentifier> extendedKeyUsage) {
        this.extendedKeyUsage = extendedKeyUsage;
    }

}
