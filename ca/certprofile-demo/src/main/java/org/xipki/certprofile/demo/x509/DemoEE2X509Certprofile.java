/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.certprofile.demo.x509;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.CertprofileException;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.api.profile.ExtensionControl;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.KeyParametersOption;
import org.xipki.ca.api.profile.CertValidity.Unit;
import org.xipki.ca.api.profile.x509.AbstractEEX509Certprofile;
import org.xipki.ca.api.profile.x509.KeyUsageControl;
import org.xipki.common.KeyUsage;

/**
 * @author Lijun Liao
 */

public class DemoEE2X509Certprofile extends AbstractEEX509Certprofile
{
    private final CertValidity validity;
    private final Set<KeyUsageControl> keyUsage;
    private final Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls;

    public DemoEE2X509Certprofile()
    {
        validity = new CertValidity(10, Unit.YEAR);

        Set<KeyUsageControl> _keyUsage = new HashSet<>(2);
        _keyUsage.add(new KeyUsageControl(KeyUsage.digitalSignature, true));
        _keyUsage.add(new KeyUsageControl(KeyUsage.dataEncipherment, true));
        keyUsage = Collections.unmodifiableSet(_keyUsage);

        extensionControls = new HashMap<>();
        extensionControls.put(Extension.authorityKeyIdentifier,
                new ExtensionControl(false, true, false));
        extensionControls.put(Extension.freshestCRL,
                new ExtensionControl(false, false, false));
        extensionControls.put(Extension.issuerAlternativeName,
                new ExtensionControl(false, false, false));
        extensionControls.put(Extension.subjectKeyIdentifier,
                new ExtensionControl(false, true, false));
        extensionControls.put(Extension.cRLDistributionPoints,
                new ExtensionControl(false, false, false));
        extensionControls.put(Extension.authorityKeyIdentifier,
                new ExtensionControl(false, true, false));
        extensionControls.put(Extension.authorityInfoAccess,
                new ExtensionControl(false, false, false));
        extensionControls.put(Extension.basicConstraints,
                new ExtensionControl(true, true, false));
        extensionControls.put(Extension.keyUsage,
                new ExtensionControl(true, true, true));
    }

    @Override
    public Set<KeyUsageControl> getKeyUsage()
    {
        return keyUsage;
    }

    @Override
    public CertValidity getValidity()
    {
        return validity;
    }

    @Override
    public Map<ASN1ObjectIdentifier, ExtensionControl> getExtensionControls()
    {
        return extensionControls;
    }

    @Override
    public ExtensionValues getExtensions(
            Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls,
            X500Name requestedSubject, Extensions requestedExtensions)
    throws CertprofileException, BadCertTemplateException
    {
        return null;
    }

    @Override
    protected Map<ASN1ObjectIdentifier, KeyParametersOption> getKeyAlgorithms()
    {
        return null;
    }

}
