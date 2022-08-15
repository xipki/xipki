/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.cmpclient;

import org.xipki.util.FileOrBinary;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.http.SslConf;

import java.util.LinkedList;
import java.util.List;

/**
 * Configuration of CMP client.
 *
 * @author Lijun Liao
 */

public class CmpClientConf extends ValidatableConf {

  public static class Responder extends ValidatableConf {

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
    public void validate()
        throws InvalidConfException {
      if (pbmMac == null && signature == null) {
        throw new InvalidConfException("at least one of pbmMac and signature must be specified");
      }
      validate(pbmMac);
      validate(signature);
    }

    public static class PbmMac extends ValidatableConf {

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
      public void validate()
          throws InvalidConfException {
        notEmpty(owfAlgos, "owfAlgos");
        notEmpty(macAlgos, "macAlgos");
      }

    } // class PbmMac

    public static class Signature extends ValidatableConf {

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
      public void validate()
          throws InvalidConfException {
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
  public void validate()
      throws InvalidConfException {
    validate(responder);
    validate(ssl);
  }

}
