/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
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

package org.xipki.pki.ca.scep.client.shell;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.commands.Command;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.xipki.scep.client.EnrolmentResponse;
import org.xipki.scep.client.ScepClient;
import org.xipki.scep.client.exception.ScepClientException;

/**
 * @author Lijun Liao
 */

@Command(scope = "scep", name = "renewal-req",
        description = "enroll certificate via messageType RenewalReq")
public class RenewalReqCmd extends AbstractEnrollCertCmd {

    @Override
    protected EnrolmentResponse requestCertificate(
            final ScepClient client,
            final CertificationRequest csr,
            final PrivateKey identityKey,
            final X509Certificate identityCert)
    throws ScepClientException {
        return client.scepRenewalReq(csr, identityKey, identityCert);
    }

}
