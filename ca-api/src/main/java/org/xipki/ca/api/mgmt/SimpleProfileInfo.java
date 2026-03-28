// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.ca.api.mgmt.entry.MgmtEntry;
import org.xipki.ca.api.profile.ctrl.CertDomain;
import org.xipki.ca.api.profile.ctrl.CertLevel;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;

/**
 * Simple information of a certificate profile.
 *
 * @author Lijun Liao (xipki)
 */
public class SimpleProfileInfo extends MgmtEntry {

  private final CertDomain certDomain;

  private final CertLevel certLevel;

  private final String validity;

  private final String keypairGen;

  public SimpleProfileInfo(CertDomain certDomain, CertLevel certLevel,
                           String validity, String keypairGen) {
    this.certDomain = Args.notNull(certDomain, "certDomain");
    this.certLevel = Args.notNull(certLevel, "certLevel");
    this.validity = Args.notBlank(validity, "validity");
    this.keypairGen = Args.notBlank(keypairGen, "keypairGen");
  }

  public CertDomain getCertDomain() {
    return certDomain;
  }

  public CertLevel getCertLevel() {
    return certLevel;
  }

  public String getValidity() {
    return validity;
  }

  public String getKeypairGen() {
    return keypairGen;
  }

  @Override
  public String toString() {
    return "CertDomain=" + certDomain + ", CertLevel=" + certLevel +
        ", Validity=" + validity + ", KeypairGen=" + keypairGen;
  }

  @Override
  public JsonMap toCodec() {
    JsonMap ret = new JsonMap();
    ret.putEnum("certDomain", certDomain);
    ret.putEnum("certLevel", certLevel);
    ret.put("validity", validity);
    ret.put("keypairGen", keypairGen);
    return ret;
  }

  public static SimpleProfileInfo parse(JsonMap json) throws CodecException {
    return new SimpleProfileInfo(
        json.getNnEnum("certDomain", CertDomain.class),
        json.getNnEnum("certLevel", CertLevel.class),
        json.getNnString("validity"),
        json.getNnString("keypairGen"));
  }

}
