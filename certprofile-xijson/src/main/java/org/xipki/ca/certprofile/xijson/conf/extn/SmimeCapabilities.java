// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 * Extension S/MIME Capabilities.
 *
 * @author Lijun Liao (xipki)
 */

public class SmimeCapabilities implements JsonEncodable {

  private final List<SmimeCapability> capabilities;

  public SmimeCapabilities(List<SmimeCapability> capabilities) {
    this.capabilities = Args.notEmpty(capabilities, "capabilities");
  }

  public List<SmimeCapability> capabilities() {
    return capabilities;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().putEncodables("capabilities", capabilities);
  }

  public static SmimeCapabilities parse(JsonMap json) throws CodecException {
    JsonList list = json.getNnList("capabilities");
    List<SmimeCapability> capabilities = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      capabilities.add(SmimeCapability.parse(v));
    }
    return new SmimeCapabilities(capabilities);
  }

  public static class SmimeCapability implements JsonEncodable {

    private final ASN1ObjectIdentifier capabilityId;

    private final Integer parameter;

    public SmimeCapability(ASN1ObjectIdentifier capabilityId,
                           Integer parameter) {
      this.capabilityId = Args.notNull(capabilityId, "capabilityId");
      this.parameter = parameter;
    }

    public ASN1ObjectIdentifier capabilityId() {
      return capabilityId;
    }

    public Integer parameter() {
      return parameter;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("capabilityId", capabilityId.getId())
          .put("parameter", parameter);
    }

    public static SmimeCapability parse(JsonMap json) throws CodecException {
      return new SmimeCapability(
          new ASN1ObjectIdentifier(json.getNnString("capabilityId")),
          json.getInt("parameter"));
    }

  } // class SmimeCapability

} // class SmimeCapabilities
