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

package org.xipki.pki.ca.demo.certprofile.x509;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.xipki.pki.ca.api.BadCertTemplateException;
import org.xipki.pki.ca.api.CertprofileException;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.api.profile.CertValidity.Unit;
import org.xipki.pki.ca.api.profile.ExtensionControl;
import org.xipki.pki.ca.api.profile.ExtensionValues;
import org.xipki.pki.ca.api.profile.KeyParametersOption;
import org.xipki.pki.ca.api.profile.RDNControl;
import org.xipki.pki.ca.api.profile.x509.AbstractEEX509Certprofile;
import org.xipki.pki.ca.api.profile.x509.KeyUsageControl;
import org.xipki.pki.ca.api.profile.x509.SubjectControl;
import org.xipki.security.api.KeyUsage;
import org.xipki.security.api.ObjectIdentifiers;

/**
 * @author Lijun Liao
 */

public class DemoEE1X509Certprofile extends AbstractEEX509Certprofile
{
    private final CertValidity validity;
    private final Set<KeyUsageControl> keyUsage;
    private final Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls;
    private final SubjectControl subjectControl;

    public DemoEE1X509Certprofile()
    {
        validity = new CertValidity(10, Unit.YEAR);

        Set<KeyUsageControl> _keyUsage = new HashSet<>();
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

        Map<ASN1ObjectIdentifier, RDNControl> controls = new HashMap<>();

        ASN1ObjectIdentifier oid = ObjectIdentifiers.DN_O;
        controls.put(oid, new RDNControl(oid, 1, 1));

        oid = ObjectIdentifiers.DN_OU;
        controls.put(oid, new RDNControl(oid, 0, 1));

        oid = ObjectIdentifiers.DN_C;
        controls.put(oid, new RDNControl(oid, 1, 1));

        subjectControl = new SubjectControl(false, controls);
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
            final Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls,
            final X500Name requestedSubject,
            final Extensions requestedExtensions,
            final Date notBefore,
            final Date notAfter)
    throws CertprofileException, BadCertTemplateException
    {
        return null;
    }

    @Override
    protected Map<ASN1ObjectIdentifier, KeyParametersOption> getKeyAlgorithms()
    {
        return null;
    }

    @Override
    protected SubjectControl getSubjectControl()
    {
        return subjectControl;
    }

}
