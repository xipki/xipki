/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.litecaclient;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;

/**
 * @author Lijun Liao
 */

public class SdkUtil {

    private static CertificateFactory certFact;
    private static Object certFactLock = new Object();

    private SdkUtil() {
    }

    public static X509Certificate parseCert(final File file)
            throws IOException, CertificateException {
        requireNonNull("file", file);
        FileInputStream in = new FileInputStream(file);
        try {
            return parseCert(in);
        } finally {
            in.close();
        }
    }

    public static X509Certificate parseCert(final byte[] certBytes)
            throws CertificateException {
        requireNonNull("certBytes", certBytes);
        return parseCert(new ByteArrayInputStream(certBytes));
    }

    public static X509Certificate parseCert(final InputStream certStream)
            throws CertificateException {
        requireNonNull("certStream", certStream);
        X509Certificate cert = (X509Certificate) getCertFactory().generateCertificate(certStream);
        if (cert == null) {
            throw new CertificateEncodingException(
                    "the given one is not a valid X.509 certificate");
        }
        return cert;
    }

    private static CertificateFactory getCertFactory() throws CertificateException {
        synchronized (certFactLock) {
            if (certFact == null) {
                certFact = CertificateFactory.getInstance("X.509");
            }
            return certFact;
        }
    }

    public static byte[] extractSki(final X509Certificate cert)
            throws CertificateEncodingException {
        byte[] fullExtValue = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        if (fullExtValue == null) {
            return null;
        }

        byte[] extValue = ASN1OctetString.getInstance(fullExtValue).getOctets();
        return ASN1OctetString.getInstance(extValue).getOctets();
    }

    public static byte[] read(final File file) throws IOException {
        return read(new FileInputStream(file));
    }

    public static byte[] read(final InputStream in) throws IOException {
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            int readed = 0;
            byte[] buffer = new byte[2048];
            while ((readed = in.read(buffer)) != -1) {
                bout.write(buffer, 0, readed);
            }

            return bout.toByteArray();
        } finally {
            try {
                in.close();
            } catch (IOException ex) {
            }
        }
    }

    public static void save(final File file, final byte[] content) throws IOException {
        File parent = file.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        FileOutputStream out = new FileOutputStream(file);
        try {
            out.write(content);
        } finally {
            out.close();
        }
    }

    public static HttpURLConnection openHttpConn(final URL url)
            throws IOException {
        requireNonNull("url", url);
        URLConnection conn = url.openConnection();
        if (conn instanceof HttpURLConnection) {
            return (HttpURLConnection) conn;
        }
        throw new IOException(url.toString() + " is not of protocol HTTP: " + url.getProtocol());
    }

    public static <T> T requireNonNull(final String objName, final T obj) {
        return Objects.requireNonNull(obj, objName + " must not be null");
    }

    public static String requireNonBlank(final String objName, final String obj) {
        Objects.requireNonNull(obj, objName + " must not be null");
        if (obj.isEmpty()) {
            throw new IllegalArgumentException(objName + " must not be blank");
        }
        return obj;
    }

}
