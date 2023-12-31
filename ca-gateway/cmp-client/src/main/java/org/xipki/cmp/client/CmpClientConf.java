// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

import org.xipki.util.FileOrBinary;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.http.SslConf;

import java.util.LinkedList;
import java.util.List;

/**
 * Configuration of CMP client.
 *
 * @author Lijun Liao (xipki)
 */

public class CmpClientConf extends ValidableConf {

  public static class Responder extends ValidableConf {

    private String url;

    private Responder.PbmMac pbmMac;

    private Responder.Signature signature;

    private FileOrBinary dhPopCerts;

    public String getUrl() {
      return url;
    }

    public void setUrl(String url) {
      this.url = url;
    }

    public Responder.PbmMac getPbmMac() {
      return pbmMac;
    }

    public void setPbmMac(Responder.PbmMac value) {
      this.pbmMac = value;
    }

    public Responder.Signature getSignature() {
      return signature;
    }

    public void setSignature(Responder.Signature value) {
      this.signature = value;
    }

    public FileOrBinary getDhPopCerts() {
      return dhPopCerts;
    }

    public void setDhPopCerts(FileOrBinary dhPopCerts) {
      this.dhPopCerts = dhPopCerts;
    }

    @Override
    public void validate() throws InvalidConfException {
      if (pbmMac == null && signature == null) {
        throw new InvalidConfException("at least one of pbmMac and signature must be specified");
      }
      validate(pbmMac, signature);
    }

    public static class PbmMac extends ValidableConf {

      private List<String> owfAlgos;

      private List<String> macAlgos;

      public List<String> getOwfAlgos() {
        if (owfAlgos == null) {
          owfAlgos = new LinkedList<>();
        }
        return owfAlgos;
      }

      public void setOwfAlgos(List<String> owfAlgos) {
        this.owfAlgos = owfAlgos;
      }

      public List<String> getMacAlgos() {
        if (macAlgos == null) {
          macAlgos = new LinkedList<>();
        }
        return macAlgos;
      }

      public void setMacAlgos(List<String> macAlgos) {
        this.macAlgos = macAlgos;
      }

      @Override
      public void validate() throws InvalidConfException {
        notEmpty(owfAlgos, "owfAlgos");
        notEmpty(macAlgos, "macAlgos");
      }

    } // class PbmMac

    public static class Signature extends ValidableConf {

      private FileOrBinary cert;

      private List<String> signatureAlgos;

      public FileOrBinary getCert() {
        return cert;
      }

      public void setCert(FileOrBinary cert) {
        this.cert = cert;
      }

      public List<String> getSignatureAlgos() {
        if (signatureAlgos == null) {
          signatureAlgos = new LinkedList<>();
        }
        return signatureAlgos;
      }

      public void setSignatureAlgos(List<String> signatureAlgos) {
        this.signatureAlgos = signatureAlgos;
      }

      @Override
      public void validate() throws InvalidConfException {
        notEmpty(signatureAlgos, "signatureAlgos");
      }

    } // class Signature

  } // class Responder

  private boolean sendRequestorCert = true;

  private Responder responder;

  private SslConf ssl;

  public boolean isSendRequestorCert() {
    return sendRequestorCert;
  }

  public void setSendRequestorCert(boolean sendRequestorCert) {
    this.sendRequestorCert = sendRequestorCert;
  }

  public Responder getResponder() {
    return responder;
  }

  public void setResponder(Responder responder) {
    this.responder = responder;
  }

  public SslConf getSsl() {
    return ssl;
  }

  public void setSsl(SslConf ssl) {
    this.ssl = ssl;
  }

  @Override
  public void validate() throws InvalidConfException {
    validate(responder, ssl);
  }

}
