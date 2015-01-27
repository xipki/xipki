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

package org.xipki.common;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * @author Lijun Liao
 */

public class CustomObjectIdentifiers
{
    private static final ASN1ObjectIdentifier id_private_dummy = new ASN1ObjectIdentifier("1.2.3.4.5.6");

    private static final ASN1ObjectIdentifier id_ext                      = id_private_dummy.branch("1");
    private static final ASN1ObjectIdentifier id_cmp                      = id_private_dummy.branch("2");
    private static final ASN1ObjectIdentifier id_remotep11                = id_private_dummy.branch("3");

    public static final ASN1ObjectIdentifier id_ext_crl_certset           = id_ext.branch("1");

    public static final ASN1ObjectIdentifier id_cmp_generateCRL           = id_cmp.branch("1");
    public static final ASN1ObjectIdentifier id_cmp_request_extensions    = id_cmp.branch("2");

    public static final ASN1ObjectIdentifier id_cmp_getSystemInfo         = id_cmp.branch("3");
    public static final ASN1ObjectIdentifier id_cmp_removeExpiredCerts    = id_cmp.branch("4");

    public static final ASN1ObjectIdentifier id_remotep11_version         = id_remotep11.branch("1");
    public static final ASN1ObjectIdentifier id_remotep11_pso_rsa_x509    = id_remotep11.branch("2");
    public static final ASN1ObjectIdentifier id_remotep11_pso_rsa_pkcs    = id_remotep11.branch("3");
    public static final ASN1ObjectIdentifier id_remotep11_pso_ecdsa       = id_remotep11.branch("4");
    public static final ASN1ObjectIdentifier id_remotep11_pso_dsa         = id_remotep11.branch("5");
    public static final ASN1ObjectIdentifier id_remotep11_get_publickey   = id_remotep11.branch("11");
    public static final ASN1ObjectIdentifier id_remotep11_get_certificate = id_remotep11.branch("12");
    public static final ASN1ObjectIdentifier id_remotep11_list_slots      = id_remotep11.branch("13");
    public static final ASN1ObjectIdentifier id_remotep11_list_keylabels  = id_remotep11.branch("14");

    public static final GeneralName CMP_SERVER =
            new GeneralName(GeneralName.uniformResourceIdentifier, "http://xipki.org/remotep11/server");
    public static final GeneralName CMP_CLIENT =
            new GeneralName(GeneralName.uniformResourceIdentifier, "http://xipki.org/remotep11/client");

}
