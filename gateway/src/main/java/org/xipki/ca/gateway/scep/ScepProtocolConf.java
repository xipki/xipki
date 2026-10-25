// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.scep;

import org.xipki.ca.gateway.GatewayConf;
import org.xipki.ca.sdk.SdkClientConf;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.json.JsonList;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.codec.exception.InvalidConfException;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * SCEP Protocol configuration.
 *
 * @author Lijun Liao (xipki)
 */
public class ScepProtocolConf extends GatewayConf.ProtocolConf {

  private final ScepControl scep;

  private final String authenticator;

  private final List<GatewayConf.CaProfileConf> caProfiles;

  /**
   * The signers.
   */
  private final GatewayConf.CaNameSignersConf signers;

  /**
   * The decryptors. If not set (for a CA), the key of the signer is used for the decryption.
   */
  private final CaNameDecryptorsConf decryptors;

  public ScepProtocolConf(
      Boolean logReqResp, GatewayConf.PopControlConf pop, SdkClientConf sdkClient,
      ScepControl scep, String authenticator, List<GatewayConf.CaProfileConf> caProfiles,
      GatewayConf.CaNameSignersConf signers, CaNameDecryptorsConf decryptors) {
    super(logReqResp, pop, sdkClient);
    this.scep = Args.notNull(scep, "scep");
    this.authenticator = Args.notBlank(authenticator, "authenticator");
    this.caProfiles = caProfiles;
    this.signers = Args.notNull(signers, "signers");
    this.decryptors = decryptors;
    if (caProfiles != null) {
      try {
        new GatewayConf.CaProfilesControl(caProfiles);
      } catch (InvalidConfException e) {
        throw new IllegalArgumentException(e);
      }
    }
  }

  public ScepControl scep() {
    return scep;
  }

  public String authenticator() {
    return authenticator;
  }

  public List<GatewayConf.CaProfileConf> caProfiles() {
    return caProfiles;
  }

  public GatewayConf.CaNameSignersConf signers() {
    return signers;
  }

  public CaNameDecryptorsConf decryptors() {
    return decryptors;
  }

  public static ScepProtocolConf parse(JsonMap json) throws CodecException {
    GatewayConf.ProtocolConf pConf = GatewayConf.ProtocolConf.parse0(json);

    JsonMap map = json.getMap("scep");
    ScepControl scep = (map == null) ? null : ScepControl.parse(map);

    JsonList list = json.getList("caProfiles");
    List<GatewayConf.CaProfileConf> caProfiles = null;
    if (list != null) {
      caProfiles = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        caProfiles.add(GatewayConf.CaProfileConf.parse(v));
      }
    }

    map = json.getNnMap("signers");
    GatewayConf.CaNameSignersConf signers = GatewayConf.CaNameSignersConf.parse(map);

    map = json.getMap("decryptors");
    CaNameDecryptorsConf decryptors = (map == null) ? null : CaNameDecryptorsConf.parse(map);

    return new ScepProtocolConf(pConf.logReqResp(), pConf.pop(),
        pConf.sdkClient(), scep, json.getString("authenticator"), caProfiles, signers,
        decryptors);
  }

  public static ScepProtocolConf readConfFromFile(String fileName) throws InvalidConfException {
    Args.notBlank(fileName, "fileName");

    try {
      return parse(JsonParser.parseMap(Paths.get(fileName), true));
    } catch (CodecException e) {
      throw new InvalidConfException("error parsing ScepProtocolConf: " + e.getMessage(), e);
    }
  }

  /**
   * Decryptor of the CAs with given names.
   */
  public static class CaNameDecryptorConf {

    private final List<String> names;

    private final GatewayConf.SignerConf decryptor;

    public CaNameDecryptorConf(GatewayConf.SignerConf decryptor, List<String> names) {
      this.names = Args.notEmpty(names, "names");
      this.decryptor = Args.notNull(decryptor, "decryptor");
    }

    public List<String> names() {
      return names;
    }

    public GatewayConf.SignerConf decryptor() {
      return decryptor;
    }

    public static CaNameDecryptorConf parse(JsonMap json) throws CodecException {
      JsonMap map = json.getNnMap("decryptor");
      return new CaNameDecryptorConf(GatewayConf.SignerConf.parse(map),
          json.getNnStringList("names"));
    }

  }

  /**
   * Decryptors configuration. The decryptor is configured as the signer, but only the type
   * pkcs12 is supported.
   */
  public static class CaNameDecryptorsConf {

    private final GatewayConf.SignerConf default_;

    private final List<CaNameDecryptorConf> decryptors;

    public CaNameDecryptorsConf(GatewayConf.SignerConf default_,
                                List<CaNameDecryptorConf> decryptors) {
      this.default_ = default_;
      this.decryptors = decryptors;
    }

    public GatewayConf.SignerConf getDefault() {
      return default_;
    }

    public List<CaNameDecryptorConf> decryptors() {
      return decryptors;
    }

    public static CaNameDecryptorsConf parse(JsonMap json) throws CodecException {
      JsonMap map = json.getMap("default");
      GatewayConf.SignerConf default_ = (map == null) ? null : GatewayConf.SignerConf.parse(map);
      JsonList list = json.getList("decryptors");
      List<CaNameDecryptorConf> decryptors = null;
      if (list != null) {
        decryptors = new ArrayList<>(list.size());
        for (JsonMap v : list.toMapList()) {
          decryptors.add(CaNameDecryptorConf.parse(v));
        }
      }

      return new CaNameDecryptorsConf(default_, decryptors);
    }

  }

}
