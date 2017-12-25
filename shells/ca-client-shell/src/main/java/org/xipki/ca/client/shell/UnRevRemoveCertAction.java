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

package org.xipki.ca.client.shell;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.xipki.ca.client.shell.completer.CaNameCompleter;
import org.xipki.common.util.ParamUtil;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class UnRevRemoveCertAction extends ClientAction {

    @Option(name = "--ca",
            description = "CA name\n"
                    + "(required if more than one CA is configured)")
    @Completion(CaNameCompleter.class)
    protected String caName;

    @Option(name = "--cert", aliases = "-c",
            description = "certificate file (either cert or serial must be specified)")
    @Completion(FilePathCompleter.class)
    protected String certFile;

    @Option(name = "--serial", aliases = "-s",
            description = "serial number (either cert or serial must be specified)")
    private String serialNumberS;

    private BigInteger serialNumber;

    protected BigInteger getSerialNumber() {
        if (serialNumber == null) {
            if (isNotBlank(serialNumberS)) {
                this.serialNumber = toBigInt(serialNumberS);
            }
        }
        return serialNumber;
    }

    protected String checkCertificate(final X509Certificate cert, final X509Certificate caCert)
            throws CertificateEncodingException {
        ParamUtil.requireNonNull("cert", cert);
        ParamUtil.requireNonNull("caCert", caCert);

        if (!cert.getIssuerX500Principal().equals(caCert.getSubjectX500Principal())) {
            return "the given certificate is not issued by the given issuer";
        }

        byte[] caSki = X509Util.extractSki(caCert);
        byte[] aki = X509Util.extractAki(cert);
        if (caSki != null && aki != null) {
            if (!Arrays.equals(aki, caSki)) {
                return "the given certificate is not issued by the given issuer";
            }
        }

        try {
            cert.verify(caCert.getPublicKey(), "BC");
        } catch (SignatureException ex) {
            return "could not verify the signature of given certificate by the issuer";
        } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException
                | NoSuchProviderException ex) {
            return "could not verify the signature of given certificate by the issuer: "
                    + ex.getMessage();
        }

        return null;
    }

}
