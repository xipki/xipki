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
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.common.util.Hex;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.console.karaf.completer.HashAlgCompleter;
import org.xipki.security.HashAlgoType;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

@Command(scope = "xi", name = "cert-info",
        description = "print certificate information")
@Service
public class CertInfoCmd extends SecurityAction {

    @Option(name = "--in",
            description = "certificate file\n(required)")
    @Completion(FilePathCompleter.class)
    private String inFile;

    @Option(name = "--hex", aliases = "-h",
            description = "print hex number")
    private Boolean hex = Boolean.FALSE;

    @Option(name = "--serial",
            description = "print serial number")
    private Boolean serial;

    @Option(name = "--subject",
            description = "print subject")
    private Boolean subject;

    @Option(name = "--issuer",
            description = "print issuer")
    private Boolean issuer;

    @Option(name = "--not-before",
            description = "print notBefore")
    private Boolean notBefore;

    @Option(name = "--not-after",
            description = "print notAfter")
    private Boolean notAfter;

    @Option(name = "--fingerprint",
            description = "print fingerprint in hex")
    private Boolean fingerprint;

    @Option(name = "--hash",
            description = "hash algorithm name")
    @Completion(HashAlgCompleter.class)
    protected String hashAlgo = "SHA256";

    @Override
    protected Object execute0() throws Exception {
        Certificate cert = Certificate.getInstance(IoUtil.read(inFile));

        if (serial != null && serial) {
            return getNumber(cert.getSerialNumber().getPositiveValue());
        } else if (subject != null && subject) {
            return cert.getSubject().toString();
        } else if (issuer != null && issuer) {
            return cert.getIssuer().toString();
        } else if (notBefore != null && notBefore) {
            return toUtcTimeyyyyMMddhhmmssZ(cert.getStartDate().getDate());
        } else if (notAfter != null && notAfter) {
            return toUtcTimeyyyyMMddhhmmssZ(cert.getEndDate().getDate());
        } else if (fingerprint != null && fingerprint) {
            byte[] encoded = cert.getEncoded();
            return HashAlgoType.getHashAlgoType(hashAlgo).hexHash(encoded);
        }

        return null;
    }

    private String getNumber(Number no) {
        if (!hex) {
            return no.toString();
        }

        if (no instanceof Byte) {
            return "0X" + Hex.encodeToString(new byte[]{(byte) no});
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
