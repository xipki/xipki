/*
 * Copyright (c) 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.security.test;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.io.*;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;

public class HttpsClientTestor
{

    public static void main(String[] args)
    {
        System.out.println("HELLO".hashCode());
        System.out.println(("HELLO world a bd  wee 234  24  12  wer   wre243popokh  hzjasda  wreafy  awqasfd  asfaf" +
        "HELLO world a bd  wee 234  24  12  wer   wre243popokh  hzjasda  wreafy  awqasfd  asfaf").hashCode());
        System.out.println(hashCode("HELLO"));
        System.out.println(hashCode("HELLO world a bd  wee 234  24  12  wer   wre243popokh  hzjasda  wreafy  awqasfd  asfaf" +
        "HELLO world a bd  wee 234  24  12  wer   wre243popokh  hzjasda  wreafy  awqasfd  asfaf"));
        System.exit(1);
        try
        {
            prepare();
        }catch (Exception e)
        {
            e.printStackTrace();
            return;
        }

        new HttpsClientTestor().testIt();
    }

    public static long hashCode(String s)
    {
        long h = 0;
        char[] value = s.toCharArray();
        if (h == 0 && value.length > 0)
        {
            char val[] = value;

            for (int i = 0; i < value.length; i++)
            {
                h = 31 * h + val[i];
            }
        }
        return h;
    }

    private static void prepare()
    throws NoSuchAlgorithmException
    {
        System.setProperty("https.protocols", "TLSv1.2,TLSv1.1,TLSv1");
        //System.setProperty("javax.net.ssl.trustStore", "/home/lliao/Downloads/jetty-distribution-7.6.15.v20140411/etc/keystore");
        //System.setProperty("javax.net.ssl.trustStorePassword", "storepwd");

        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
                new javax.net.ssl.HostnameVerifier()
                {
                    public boolean verify(String hostname, javax.net.ssl.SSLSession sslSession)
                    {
                        return true;
                    }
                });
        }

    private void testIt()
    {
        String https_url = "https://localhost:9443";
        URL url;
        try
        {
            url = new URL(https_url);
            HttpsURLConnection con = (HttpsURLConnection)url.openConnection();

            //dumpl all cert info
            print_https_cert(con);

            //dump all the content
            //print_content(con);

        } catch (MalformedURLException e)
        {
         e.printStackTrace();
      } catch (IOException e)
      {
         e.printStackTrace();
      }

   }

   private void print_https_cert(HttpsURLConnection con)
   {

    if(con!=null)
    {

      try
      {

    System.out.println("Response Code : " + con.getResponseCode());
    System.out.println("Cipher Suite : " + con.getCipherSuite());
    System.out.println("\n");

    Certificate[] certs = con.getServerCertificates();
    for(Certificate cert : certs)
    {
       System.out.println("Cert Type : " + cert.getType());
       System.out.println("Cert Hash Code : " + cert.hashCode());
       System.out.println("Cert Public Key Algorithm : "
                                    + cert.getPublicKey().getAlgorithm());
       System.out.println("Cert Public Key Format : "
                                    + cert.getPublicKey().getFormat());
       System.out.println("\n");
    }

    } catch (SSLPeerUnverifiedException e)
    {
        //System.err.println(e.getMessage());
        e.printStackTrace();
    } catch (IOException e)
    {
        //System.err.println(e.getMessage());
        e.printStackTrace();
    }

     }

   }

   private void print_content(HttpsURLConnection con)
   {
    if(con!=null)
    {

    try
    {

       System.out.println("****** Content of the URL ********");
       BufferedReader br =
        new BufferedReader(
            new InputStreamReader(con.getInputStream()));

       String input;

       while ((input = br.readLine()) != null)
       {
          System.out.println(input);
       }
       br.close();

    } catch (IOException e)
    {
       e.printStackTrace();
    }

       }

   }

}
