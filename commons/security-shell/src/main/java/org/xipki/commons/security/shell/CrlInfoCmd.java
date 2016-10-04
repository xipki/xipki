/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.commons.security.shell;

import java.math.BigInteger;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

@Command(scope = "xipki-tk", name = "crl-info",
        description = "return CRL information")
@Service
public class CrlInfoCmd extends SecurityCommandSupport {

    @Option(name = "--in",
            description = "CRL file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String inFile;

    @Option(name = "--hex", aliases = "-h",
            description = "return hex number")
    private Boolean hex = Boolean.FALSE;

    @Option(name = "--crlnumber", description = "return CRL number")
    private Boolean crlNumber;

    @Option(name = "--issuer", description = "return issuer")
    private Boolean issuer;

    @Option(name = "--this-update", description = "return thisUpdate")
    private Boolean notBefore;

    @Option(name = "--next-update", description = "return nextUpdate")
    private Boolean notAfter;

    @Override
    protected Object doExecute() throws Exception {
        CertificateList crl = CertificateList.getInstance(IoUtil.read(inFile));

        if (crlNumber != null && crlNumber) {
            ASN1Encodable asn1 = crl.getTBSCertList().getExtensions().getExtensionParsedValue(
                    Extension.cRLNumber);
            if (asn1 == null) {
                return "null";
            }
            return getNumber(ASN1Integer.getInstance(asn1).getPositiveValue());
        } else if (issuer != null && issuer) {
            return crl.getIssuer().toString();
        } else if (notBefore != null && notBefore) {
            return crl.getThisUpdate().getTime();
        } else if (notAfter != null && notAfter) {
            return crl.getNextUpdate().getTime();
        }
        return null;
    }

    private String getNumber(Number no) {
        if (!hex) {
            return no.toString();
        }

        if (no instanceof Byte) {
            return "0X" + Hex.toHexString(new byte[]{(byte) no});
        } else if (no instanceof Short) {
            return "0X" + Integer.toHexString(Integer.valueOf((short) no));
        } else if (no instanceof Integer) {
            return "0X" + Integer.toHexString((int) no);
        } else if (no instanceof Long) {
            return "0X" + Long.toHexString((long) no);
        } else if (no instanceof Long) {
            return "0X" + Long.toHexString((long) no);
        } else if (no instanceof BigInteger) {
            return "0X" + ((BigInteger) no).toString(16);
        } else {
            return no.toString();
        }
    }

}
