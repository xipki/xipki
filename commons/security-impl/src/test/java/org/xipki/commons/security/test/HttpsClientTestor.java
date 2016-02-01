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

package org.xipki.commons.security.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;

/**
 * @author Lijun Liao
 */

public class HttpsClientTestor {

    private static void prepare()
    throws NoSuchAlgorithmException {
        System.setProperty("https.protocols", "TLSv1.2,TLSv1.1,TLSv1");
        //System.setProperty("javax.net.ssl.trustStore",
        // "/home/lliao/Downloads/jetty-distribution-7.6.15.v20140411/etc/keystore");
        //System.setProperty("javax.net.ssl.trustStorePassword", "storepwd");

        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
                new javax.net.ssl.HostnameVerifier() {
                    public boolean verify(String hostname, javax.net.ssl.SSLSession sslSession) {
                        return true;
                    }
                });
        }

    private void testIt() {
        String https_url = "https://localhost:9443";
        URL url;
        try {
            url = new URL(https_url);
            HttpsURLConnection con = (HttpsURLConnection)url.openConnection();

            //dumpl all cert info
            print_https_cert(con);

            //dump all the content
            //print_content(con);

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void print_https_cert(
            final HttpsURLConnection con) {
        if (con!=null) {
            try {
                System.out.println("Response Code : " + con.getResponseCode());
                System.out.println("Cipher Suite : " + con.getCipherSuite());
                System.out.println("\n");

                Certificate[] certs = con.getServerCertificates();
                for (Certificate cert : certs) {
                    System.out.println("Cert Type : " + cert.getType());
                    System.out.println("Cert Hash Code : " + cert.hashCode());
                    System.out.println("Cert Public Key Algorithm : "
                            + cert.getPublicKey().getAlgorithm());
                    System.out.println("Cert Public Key Format : "
                            + cert.getPublicKey().getFormat());
                    System.out.println("\n");
                }

            } catch (SSLPeerUnverifiedException e) {
                //System.err.println(e.getMessage());
                e.printStackTrace();
            } catch (IOException e) {
                //System.err.println(e.getMessage());
                e.printStackTrace();
            }
        }
    }

    @SuppressWarnings("unused")
    private void print_content(
            final HttpsURLConnection con) {
        if (con!=null) {
            try {
                System.out.println("****** Content of the URL ********");
                BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));

                String input;

                while ((input = br.readLine()) != null) {
                    System.out.println(input);
                }
                br.close();
            } catch (IOException e) {
            }
        }
    }

    public static void main(String[] args) {
        System.out.println("HELLO".hashCode());
        System.out.println(("HELLO world a bd  wee 234  24  12  wer   wre243popokh "
                + "HELLO world a bd  wee 234  24  12  wer   wre243popokh  hzjasda").hashCode());
        System.out.println(hashCode("HELLO"));
        System.out.println(hashCode("HELLO world a bd  wee 234  24  12  wer   wre243popokh "
                + "HELLO world a bd  wee 234  24  12  wer   wre243popokh  hzjasda"));
        System.exit(1);
        try {
            prepare();
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        new HttpsClientTestor().testIt();
    }

    public static long hashCode(
            final String s) {
        long h = 0;
        char[] value = s.toCharArray();
        if (h == 0 && value.length > 0) {
            char val[] = value;

            for (int i = 0; i < value.length; i++) {
                h = 31 * h + val[i];
            }
        }
        return h;
    }

}
