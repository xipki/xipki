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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.security.cert.X509CRL;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.commons.console.karaf.CmdFailure;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.commons.security.api.HashCalculator;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.commons.security.api.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-tk", name = "extract-cert",
        description = "extract certificates from CRL")
@Service
public class ExtractCertFromCrlCmd extends SecurityCommandSupport {

    @Option(name = "--crl",
            required = true,
            description = "CRL file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String crlFile;

    @Option(name = "--out", aliases = "-o",
            required = true,
            description = "zip file to save the extracted certificates\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Override
    protected Object doExecute()
    throws Exception {
        X509CRL crl = X509Util.parseCrl(crlFile);
        String oidExtnCerts = ObjectIdentifiers.id_xipki_ext_crlCertset.getId();
        byte[] extnValue = crl.getExtensionValue(oidExtnCerts);
        if (extnValue == null) {
            throw new IllegalCmdParamException("no certificate is contained in " + crlFile);
        }

        extnValue = removingTagAndLenFromExtensionValue(extnValue);
        ASN1Set asn1Set = DERSet.getInstance(extnValue);
        int n = asn1Set.size();
        if (n == 0) {
            throw new CmdFailure("no certificate is contained in " + crlFile);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ZipOutputStream zip = new ZipOutputStream(out);

        for (int i = 0; i < n; i++) {
            ASN1Encodable asn1 = asn1Set.getObjectAt(i);
            Certificate cert;
            try {
                ASN1Sequence seq = ASN1Sequence.getInstance(asn1);
                cert = Certificate.getInstance(seq.getObjectAt(0));
            } catch (IllegalArgumentException e) {
                // backwards compatibility
                cert = Certificate.getInstance(asn1);
            }

            byte[] certBytes = cert.getEncoded();
            String sha1FpCert = HashCalculator.hexSha1(certBytes);

            ZipEntry certZipEntry = new ZipEntry(sha1FpCert + ".der");
            zip.putNextEntry(certZipEntry);
            try {
                zip.write(certBytes);
            } finally {
                zip.closeEntry();
            }
        }

        zip.flush();
        zip.close();

        saveVerbose("extracted " + n + " certificates to", new File(outFile), out.toByteArray());
        return null;
    } // method doExecute

    private static byte[] removingTagAndLenFromExtensionValue(
            final byte[] encodedExtensionValue) {
        DEROctetString derOctet = (DEROctetString) DEROctetString.getInstance(
                encodedExtensionValue);
        return derOctet.getOctets();
    }

}
