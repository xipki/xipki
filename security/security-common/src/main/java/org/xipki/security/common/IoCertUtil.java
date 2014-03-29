/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This work is part of XiPKI, owned by Lijun Liao (lijun.liao@gmail.com)
 *
 */

package org.xipki.security.common;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class IoCertUtil {

	public static byte[] read(String fileName) throws IOException {
        FileInputStream in = null;

        try {
            in = new FileInputStream(fileName);
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            int readed = 0;
            byte[] buffer = new byte[2048];
            while ((readed = in.read(buffer)) != -1) {
                bout.write(buffer, 0, readed);
            }

            return bout.toByteArray();
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                }
            }
        }
    }

	public static void save(File file, byte[] encoded)
            throws IOException {
        File parent = file.getParentFile();
        if (parent != null && parent.exists() == false) {
            parent.mkdirs();
        }

        FileOutputStream out = new FileOutputStream(file);
        try {
            out.write(encoded);
        } finally {
            out.close();
        }
    }

    private static CertificateFactory certFact;
    private static Object certFactLock = new Object();

    public static X509Certificate parseCert(String f) throws IOException, CertificateException {
    	return parseCert(new FileInputStream(f));
    	
    }
    
    public static X509Certificate parseCert(byte[] certBytes) throws IOException, CertificateException {
    	return parseCert(new ByteArrayInputStream(certBytes));
    }
    
    public static X509Certificate parseCert(InputStream certStream) throws IOException, CertificateException {
        synchronized (certFactLock) {
            if (certFact == null) {
                try {
					certFact = CertificateFactory.getInstance("X.509", "BC");
				} catch (NoSuchProviderException e) {
					throw new IOException("NoSuchProviderException: " + e.getMessage());
				}
            }
            return (X509Certificate) certFact.generateCertificate(certStream);
        }
    }
}
