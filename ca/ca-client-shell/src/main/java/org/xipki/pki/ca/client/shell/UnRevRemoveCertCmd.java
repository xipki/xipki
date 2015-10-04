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

package org.xipki.pki.ca.client.shell;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.karaf.shell.commands.Option;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public abstract class UnRevRemoveCertCmd extends ClientCmd {
    @Option(name = "--cert", aliases = "-c",
            description = "certificate file")
    protected String certFile;

    @Option(name = "--issuer", aliases = "-i",
            description = "issuer certificate file")
    protected String issuerCertFile;

    @Option(name = "--serial", aliases = "-s",
            description = "serial number")
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

    protected String checkCertificate(
            final X509Certificate cert,
            final X509Certificate caCert)
    throws CertificateEncodingException {
        if (!cert.getIssuerX500Principal().equals(caCert.getSubjectX500Principal())) {
            return "the given certificate is not issued by the given issuer";
        }

        byte[] caSki = X509Util.extractSKI(caCert);
        byte[] aki = X509Util.extractAKI(cert);
        if (caSki != null && aki != null) {
            if (!Arrays.equals(aki, caSki)) {
                return "the given certificate is not issued by the given issuer";
            }
        }

        try {
            cert.verify(caCert.getPublicKey(), "BC");
        } catch (SignatureException e) {
            return "could not verify the signaure of given certificate by the issuer";
        } catch (InvalidKeyException
                | CertificateException
                | NoSuchAlgorithmException
                | NoSuchProviderException e) {
            return "could not verify the signaure of given certificate by the issuer: "
                    + e.getMessage();
        }

        return null;
    }

}
