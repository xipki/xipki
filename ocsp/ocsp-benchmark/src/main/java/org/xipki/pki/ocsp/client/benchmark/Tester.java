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

package org.xipki.pki.ocsp.client.benchmark;

import java.math.BigInteger;
import java.net.URI;
import java.util.Arrays;

import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.commons.common.util.BigIntegerRange;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.RangeBigIntegerIterator;
import org.xipki.pki.ocsp.client.api.RequestOptions;

public class Tester {

    public static void main(String[] args) {
        try {
            String issuerCertFile = "/home/lliao/source/xipki/dist/xipki-pki/"
                    + "xipki-pki-2.2.0-SNAPSHOT/output/SubCAwithCRL1.der";
            URI serverUrl = new URI("http://localhost:8080/ocsp/responder2");
            Certificate issuerCert = Certificate.getInstance(IoUtil.read(issuerCertFile));

            BigIntegerRange serialNumbers = new BigIntegerRange(BigInteger.valueOf(1),
                    BigInteger.valueOf(2));
            RangeBigIntegerIterator serialNumberIterator =
                    new RangeBigIntegerIterator(Arrays.asList(serialNumbers), true);

            RequestOptions options = new RequestOptions();
            OcspLoadTest loadTest = new OcspLoadTest(issuerCert, serverUrl, options,
                    serialNumberIterator, 0, "dummy");
            loadTest.setDuration("30s");
            loadTest.setThreads(10);
            loadTest.test();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

}
