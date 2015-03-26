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

package org.xipki.ca.server.impl;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.common.ObjectIdentifiers;
import org.xipki.common.util.SecurityUtil;

/**
 * @author Lijun Liao
 */

class RdnUpperBounds
{
    private static final int ub_name = 32768;
    private static final int ub_common_name = 64;
    private static final int ub_locality_name = 128;
    private static final int ub_state_name = 128;
    private static final int ub_organization_name = 64;
    private static final int ub_organizational_unit_name = 64;
    private static final int ub_title = 64;
    private static final int ub_serial_number = 64;
    private static final int ub_emailaddress_length = 255;
    private static final int ub_country_name_alpha_length = 2;
    private static final int ub_pseudonym = 128;

    private static final Map<ASN1ObjectIdentifier, Integer> ubs = new HashMap<>();
    static
    {
        // Naming attributes of type X520name. Page 112 of RFC 5280
        ubs.put(ObjectIdentifiers.DN_NAME, ub_name);
        ubs.put(ObjectIdentifiers.DN_SURNAME, ub_name);
        ubs.put(ObjectIdentifiers.DN_GIVENNAME, ub_name);
        ubs.put(ObjectIdentifiers.DN_INITIALS, ub_name);
        ubs.put(ObjectIdentifiers.DN_GENERATION_QUALIFIER, ub_name);

        // Naming attributes of type X520CommonName. Page 112 of RFC 5280
        ubs.put(ObjectIdentifiers.DN_CN, ub_common_name);

        // Naming attributes of type X520LocalityName
        ubs.put(ObjectIdentifiers.DN_LOCALITYNAME, ub_locality_name);

        // Naming attributes of type X520StateOrProvinceName
        ubs.put(ObjectIdentifiers.DN_ST, ub_state_name);

        // Naming attributes of type X520OrganizationName
        ubs.put(ObjectIdentifiers.DN_O, ub_organization_name);

        // Naming attributes of type X520OrganizationalUnitName
        ubs.put(ObjectIdentifiers.DN_OU, ub_organizational_unit_name);

        // Naming attributes of type X520Title
        ubs.put(ObjectIdentifiers.DN_T, ub_title);

        // Naming attributes of type X520countryName
        ubs.put(ObjectIdentifiers.DN_C, ub_country_name_alpha_length);

        // Naming attributes of type X520SerialNumber
        ubs.put(ObjectIdentifiers.DN_SERIALNUMBER, ub_serial_number);

        // Naming attributes of type X520Pseudonym
        ubs.put(ObjectIdentifiers.DN_PSEUDONYM, ub_pseudonym);

        // Legacy attributes
        ubs.put(ObjectIdentifiers.DN_EmailAddress, ub_emailaddress_length);
    }

    public static void checkUpperBounds(
            final X500Name name)
    throws BadCertTemplateException
    {
        RDN[] rdns = name.getRDNs();
        for(RDN rdn : rdns)
        {
            for(AttributeTypeAndValue atv : rdn.getTypesAndValues())
            {
                ASN1ObjectIdentifier type = atv.getType();
                if(ubs.containsKey(type) == false)
                {
                    continue;
                }
                int ub = ubs.get(type);
                String value = SecurityUtil.rdnValueToString(atv.getValue());
                if(value.length() > ub)
                {
                    throw new BadCertTemplateException("attribute " +
                            ObjectIdentifiers.getName(type) + " overrides the upper bound (" +
                            value.length() + " > " + ub + "): '" + value + "'");
                }
            }
        }
    }
}
