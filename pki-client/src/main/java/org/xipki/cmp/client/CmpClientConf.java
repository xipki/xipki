// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.http.SslConf;
import org.xipki.util.io.FileOrBinary;

import java.util.List;

/**
 * Configuration of CMP client.
 *
 * @author Lijun Liao (xipki)
 */

public class CmpClientConf {

  public static class Responder {

    private final String url;

    private final Responder.PbmMac pbmMac;

    private final Responder.Signature signature;

    private final FileOrBinary dhPopCerts;

    public Responder(String url, PbmMac pbmMac, Signature signature,
                     FileOrBinary dhPopCerts) {
      if (pbmMac == null && signature == null) {
        throw new IllegalArgumentException(
            "at least one of pbmMac and signature must be specified");
      }

      this.url = url;
      this.pbmMac = pbmMac;
      this.signature = signature;
      this.dhPopCerts = dhPopCerts;
    }

    public String getUrl() {
      return url;
    }

    public Responder.PbmMac getPbmMac() {
      return pbmMac;
    }

    public Responder.Signature getSignature() {
      return signature;
    }

    public FileOrBinary getDhPopCerts() {
      return dhPopCerts;
    }

    public static Responder parse(JsonMap json) throws CodecException {
      JsonMap map = json.getMap("pbmMac");
      PbmMac pbmMac = (map == null) ? null : PbmMac.parse(map);

      map = json.getMap("signature");
      Signature signature = (map == null) ? null : Signature.parse(map);

      return new Responder(json.getString("url"),
          pbmMac, signature, FileOrBinary.parse(json.getMap("dhPopCerts")));
    }

    public static class PbmMac {

      private final List<String> owfAlgos;

      private final List<String> macAlgos;

      public PbmMac(List<String> owfAlgos, List<String> macAlgos) {
        this.owfAlgos = Args.notEmpty(owfAlgos, "owfAlgos");
        this.macAlgos = Args.notEmpty(macAlgos, "macAlgos");
      }

      public List<String> getOwfAlgos() {
        return owfAlgos;
      }

      public List<String> getMacAlgos() {
        return macAlgos;
      }

      public static PbmMac parse(JsonMap json) throws CodecException {
        return new PbmMac(json.getNnStringList("owfAlgos"),
            json.getNnStringList("macAlgos"));
      }

    } // class PbmMac

    public static class Signature {

      private final FileOrBinary cert;

      private final List<String> signatureAlgos;

      public Signature(FileOrBinary cert, List<String> signatureAlgos) {
        this.cert = cert;
        this.signatureAlgos = Args.notEmpty(signatureAlgos, "signatureAlgos");
      }

      public FileOrBinary getCert() {
        return cert;
      }

      public List<String> getSignatureAlgos() {
        return signatureAlgos;
      }

      public static Signature parse(JsonMap json) throws CodecException {
        return new Signature(FileOrBinary.parse(json.getMap("cert")),
            json.getStringList("signatureAlgos"));
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

  public static CmpClientConf parse(JsonMap json) throws CodecException {
    CmpClientConf ret = new CmpClientConf();
    ret.setSendRequestorCert(json.getBool("sendRequestorCert", false));
    JsonMap map = json.getMap("responder");
    if (map != null) {
      ret.setResponder(Responder.parse(map));
    }

    map = json.getMap("ssl");
    if (map != null) {
      ret.setSsl(SslConf.parse(map));
    }
    return ret;
  }

}
