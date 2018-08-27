/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.shell;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.security.cert.X509CRL;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.IllegalCmdParamException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "extract-cert", description = "extract certificates from CRL")
@Service
public class ExtractCertFromCrlAction extends SecurityAction {

  @Option(name = "--crl", required = true, description = "CRL file")
  @Completion(FileCompleter.class)
  private String crlFile;

  @Option(name = "--out", aliases = "-o", required = true,
      description = "ZIP file to save the extracted certificates")
  @Completion(FileCompleter.class)
  private String outFile;

  @Override
  protected Object execute0() throws Exception {
    X509CRL crl = X509Util.parseCrl(new File(crlFile));
    String oidExtnCerts = ObjectIdentifiers.id_xipki_ext_crlCertset.getId();
    byte[] extnValue = crl.getExtensionValue(oidExtnCerts);
    if (extnValue == null) {
      throw new IllegalCmdParamException("no certificate is contained in " + crlFile);
    }

    extnValue = removingTagAndLenFromExtensionValue(extnValue);
    ASN1Set asn1Set = DERSet.getInstance(extnValue);
    final int n = asn1Set.size();
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
      } catch (IllegalArgumentException ex) {
        // backwards compatibility
        cert = Certificate.getInstance(asn1);
      }

      byte[] certBytes = cert.getEncoded();
      String sha1FpCert = HashAlgo.SHA1.hexHash(certBytes);
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
  } // method execute0

  private static byte[] removingTagAndLenFromExtensionValue(byte[] encodedExtensionValue) {
    DEROctetString derOctet = (DEROctetString) DEROctetString.getInstance(encodedExtensionValue);
    return derOctet.getOctets();
  }

}
