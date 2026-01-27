// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.io.FileOrBinary;
import org.xipki.util.io.FileOrValue;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * Configuration the QA system.
 *
 * @author Lijun Liao
 */
public class QaconfType {

  public static class Certprofile extends FileOrValue {

    private final String name;

    public String getName() {
      return name;
    }

    private Certprofile(String name, String file, String value) {
      super(file, value);
      this.name = Args.notBlank(name, "name");
    }

    public static Certprofile ofFile(String name, String fileName) {
      return new Certprofile(name, fileName, null);
    }

    public static Certprofile ofValue(String name, String value) {
      return new Certprofile(name, null, value);
    }

    public static Certprofile parse(JsonMap json) throws CodecException {
      String name = json.getNnString("name");
      String file = json.getString("file");
      return (file != null) ? Certprofile.ofFile(name, file)
          : Certprofile.ofValue(name, json.getNnString("value"));
    }

  }

  public static class Issuer {

    private final String name;

    private final FileOrBinary cert;

    private String validityMode;

    private List<String> caIssuerUrls;

    private List<String> ocspUrls;

    private List<String> crlUrls;

    private List<String> deltaCrlUrls;

    public Issuer(String name, FileOrBinary cert) {
      this.name = Args.notBlank(name, "name");
      this.cert = Args.notNull(cert, "cert");
    }

    public FileOrBinary getCert() {
      return cert;
    }

    public String getValidityMode() {
      return validityMode;
    }

    public void setValidityMode(String validityMode) {
      this.validityMode = validityMode;
    }

    public List<String> getCaIssuerUrls() {
      if (caIssuerUrls == null) {
        caIssuerUrls = new LinkedList<>();
      }
      return caIssuerUrls;
    }

    public void setCaIssuerUrls(List<String> caIssuerUrls) {
      this.caIssuerUrls = caIssuerUrls;
    }

    public List<String> getOcspUrls() {
      if (ocspUrls == null) {
        ocspUrls = new LinkedList<>();
      }
      return ocspUrls;
    }

    public void setOcspUrls(List<String> ocspUrls) {
      this.ocspUrls = ocspUrls;
    }

    public List<String> getCrlUrls() {
      if (crlUrls == null) {
        crlUrls = new LinkedList<>();
      }
      return crlUrls;
    }

    public void setCrlUrls(List<String> crlUrls) {
      this.crlUrls = crlUrls;
    }

    public List<String> getDeltaCrlUrls() {
      if (deltaCrlUrls == null) {
        deltaCrlUrls = new LinkedList<>();
      }
      return deltaCrlUrls;
    }

    public void setDeltaCrlUrls(List<String> deltaCrlUrls) {
      this.deltaCrlUrls = deltaCrlUrls;
    }

    public String getName() {
      return name;
    }

    public static Issuer parse(JsonMap json) throws CodecException {
      Issuer ret = new Issuer(json.getNnString("name"),
          FileOrBinary.parse(json.getNnMap("cert")));
      ret.setValidityMode(json.getString("validityMode"));
      ret.setCaIssuerUrls(json.getStringList("caIssuerUrls"));
      ret.setOcspUrls(json.getStringList("ocspUrls"));
      ret.setCrlUrls(json.getStringList("crlUrls"));
      ret.setDeltaCrlUrls(json.getStringList("deltaCrlUrls"));
      return ret;
    }

  } // class Issuer

  private final List<Issuer> issuers;

  private final List<Certprofile> certprofiles;

  public QaconfType(List<Issuer> issuers, List<Certprofile> certprofiles) {
    this.issuers = (issuers == null) ? Collections.emptyList() : issuers;
    this.certprofiles = (certprofiles == null) ? Collections.emptyList()
        : certprofiles;
  }

  public List<Issuer> getIssuers() {
    return issuers;
  }

  public List<Certprofile> getCertprofiles() {
    return certprofiles;
  }

  public static QaconfType parse(JsonMap json) throws CodecException {
    JsonList list = json.getList("issuers");
    List<Issuer> issuers = new LinkedList<>();
    for (JsonMap v : list.toMapList()) {
      issuers.add(Issuer.parse(v));
    }

    list = json.getList("certprofiles");
    List<Certprofile> certprofiles = new LinkedList<>();
    for (JsonMap v : list.toMapList()) {
      certprofiles.add(Certprofile.parse(v));
    }

    return new QaconfType(issuers, certprofiles);
  }

}
