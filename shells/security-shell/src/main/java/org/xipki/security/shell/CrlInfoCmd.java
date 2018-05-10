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

import java.math.BigInteger;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.common.util.Hex;
import org.xipki.common.util.IoUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.1.0
 */

@Command(scope = "xi", name = "crl-info",
    description = "print CRL information")
@Service
public class CrlInfoCmd extends SecurityAction {

  @Option(name = "--in",
      description = "CRL file\n(required)")
  @Completion(FileCompleter.class)
  private String inFile;

  @Option(name = "--hex", aliases = "-h",
      description = "print hex number")
  private Boolean hex = Boolean.FALSE;

  @Option(name = "--crlnumber",
      description = "print CRL number")
  private Boolean crlNumber;

  @Option(name = "--issuer",
      description = "print issuer")
  private Boolean issuer;

  @Option(name = "--this-update",
      description = "print thisUpdate")
  private Boolean thisUpdate;

  @Option(name = "--next-update",
      description = "print nextUpdate")
  private Boolean nextUpdate;

  @Override
  protected Object execute0() throws Exception {
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
    } else if (thisUpdate != null && thisUpdate) {
      return toUtcTimeyyyyMMddhhmmssZ(crl.getThisUpdate().getDate());
    } else if (nextUpdate != null && nextUpdate) {
      return crl.getNextUpdate() == null ? "null" :
        toUtcTimeyyyyMMddhhmmssZ(crl.getNextUpdate().getDate());
    }

    return null;
  }

  private String getNumber(Number no) {
    if (!hex) {
      return no.toString();
    }

    if (no instanceof Byte) {
      return "0X" + Hex.encode(new byte[]{(byte) no});
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
