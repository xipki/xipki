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

public class XipkiCmpConstants
{
    private static final ASN1ObjectIdentifier id_private_dummy = new ASN1ObjectIdentifier("1.2.3.4.5.6");

    private static final ASN1ObjectIdentifier id_ext                       = id_private_dummy.branch("1");
    public static final ASN1ObjectIdentifier id_ext_crl_certset            = id_ext.branch("1");
    public static final ASN1ObjectIdentifier id_ext_cmp_request_extensions = id_ext.branch("2");

    public static final ASN1ObjectIdentifier id_xipki_cmp                  = id_private_dummy.branch("2");

    public static final GeneralName remoteP11_cmp_server =
            new GeneralName(GeneralName.uniformResourceIdentifier, "http://xipki.org/remotep11/server");
    public static final GeneralName remotep11_cmp_client =
            new GeneralName(GeneralName.uniformResourceIdentifier, "http://xipki.org/remotep11/client");

    public static final int ACTION_GEN_CRL = 1;
    public static final int ACTION_GET_CRL = 2;
    public static final int ACTION_GET_CAINFO = 3;
    public static final int ACTION_REMOVE_EXPIRED_CERTS = 4;
    public static final int ACTION_REMOTEP11_VERSION = 80;
    public static final int ACTION_REMOTEP11_PSO_RSA_X509 = 81;
    public static final int ACTION_REMOTEP11_PSO_RSA_PKCS = 82;
    public static final int ACTION_REMOTEP11_PSO_ECDSA = 83;
    public static final int ACTION_REMOTEP11_PSO_DSA = 84;
    public static final int ACTION_REMOTEP11_GET_PUBLICKEY = 85;
    public static final int ACTION_REMOTEP11_GET_CERTIFICATE = 86;
    public static final int ACTION_REMOTEP11_LIST_SLOTS = 87;
    public static final int ACTION_REMOTEP11_LIST_KEYLABELS = 88;

}
