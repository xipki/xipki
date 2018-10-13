package org.xipki.http.client;

import java.io.File;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;

public class HttpCommunicatorBuilder {
  
  private String keystoreType;
  
  private String keystoreFile;
  
  private char[] keystorePassword;
  
  private String truststoreFile;
  
  private char[] truststorePassword;
  
  private HostnameVerifier hostnameVerifier;
  
  private String userAgent;
  
  private SSLContext sslContext;
  
  public HttpCommunicatorBuilder() {
  }

  public void setKeystoreType(String keystoreType) {
    this.keystoreType = keystoreType;
  }

  public void setKeystoreFile(String keystoreFile) {
    this.keystoreFile = keystoreFile;
  }

  public void setKeystorePassword(char[] keystorePassword) {
    this.keystorePassword = keystorePassword;
  }

  public void setTruststoreFile(String truststoreFile) {
    this.truststoreFile = truststoreFile;
  }

  public void setTruststorePassword(char[] truststorePassword) {
    this.truststorePassword = truststorePassword;
  }

  public void setHostnameVerifier(HostnameVerifier hostnameVerifier) {
    this.hostnameVerifier = hostnameVerifier;
  }

  public void setUserAgent(String userAgent) {
    this.userAgent = userAgent;
  }

  public void setSslContext(SSLContext sslContext) {
    this.sslContext = sslContext;
  }

  public HttpCommunicator build() throws Exception {
    HttpClientBuilder builder = HttpClients.custom();

    if (hostnameVerifier != null) {
      builder.setSSLHostnameVerifier(hostnameVerifier);
    }
    
    if (userAgent != null) {
      builder.setUserAgent(userAgent);
    }

    if (sslContext != null) {
      builder.setSSLContext(sslContext);
    } else if (keystoreFile != null || truststoreFile != null) {
      SSLContextBuilder sslCtxBuilder = SSLContexts.custom();
      if (keystoreType != null) {
        sslCtxBuilder.setKeyStoreType(keystoreType);
      }

      SSLContext sslCtx;
      try {
        if (keystoreFile != null) {
          // both key and keystore must have the same password in our application
          char[] keyPassword = keystorePassword;
          sslCtxBuilder.loadKeyMaterial(new File(keystoreFile), keystorePassword, keyPassword);
        }
  
        if (truststoreFile != null) {
          sslCtxBuilder.loadTrustMaterial(new File(truststoreFile), truststorePassword);
        }
        
        sslCtx = sslCtxBuilder.build();
      } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException
          | UnrecoverableKeyException | KeyManagementException ex) {
        throw new Exception("error while building SSLContext", ex); 
      }

      builder.setSSLContext(sslCtx);
    }

    return new HttpCommunicator(builder.build());
    
  }
  
}
