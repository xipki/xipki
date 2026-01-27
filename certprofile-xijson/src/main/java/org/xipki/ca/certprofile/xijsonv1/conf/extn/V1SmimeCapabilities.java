// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.extn;

import org.bouncycastle.asn1.ASN1Integer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.certprofile.xijson.conf.extn.SmimeCapabilities;
import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableBinary;
import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableOid;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 * Extension S/MIME Capabilities.
 *
 * @author Lijun Liao (xipki)
 */

public class V1SmimeCapabilities {

  private static final Logger LOG =
      LoggerFactory.getLogger(V1SmimeCapabilities.class);

  private final List<SmimeCapability> capabilities;

  private V1SmimeCapabilities(List<SmimeCapability> capabilities) {
    this.capabilities = Args.notEmpty(capabilities, "capabilities");
  }

  public SmimeCapabilities toV2() {
    List<SmimeCapabilities.SmimeCapability> list =
        new ArrayList<>(capabilities.size());
    for (SmimeCapability c : capabilities) {
      Integer v2Parameter = null;
      if (c.parameter != null) {
        if (c.parameter.binary != null) {
          try {
            ASN1Integer ai = ASN1Integer.getInstance(
                c.parameter.binary.getValue());
            v2Parameter = ai.intValueExact();
          } catch (Exception e) {
            LOG.warn("ignore SmimeCapability.parameter.binary", e);
          }
        } else if (c.parameter.integer != null) {
          try {
            v2Parameter = c.parameter.integer;
          } catch (ArithmeticException e) {
            LOG.warn("SmimeCapability.parameter.integer not an int: {}",
                c.parameter.integer);
          }
        }
      }

      list.add(new SmimeCapabilities.SmimeCapability(
          c.capabilityId.oid(), v2Parameter));
    }

    return new SmimeCapabilities(list.isEmpty() ? null : list);
  }

  public static V1SmimeCapabilities parse(JsonMap json) throws CodecException {
    JsonList list = json.getNnList("capabilities");
    List<SmimeCapability> capabilities = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      capabilities.add(SmimeCapability.parse(v));
    }
    return new V1SmimeCapabilities(capabilities);
  }

  private static class SmimeCapability {

    private final DescribableOid capabilityId;

    private final SmimeCapabilityParameter parameter;

    public SmimeCapability(DescribableOid capabilityId,
                           SmimeCapabilityParameter parameter) {
      this.capabilityId = Args.notNull(capabilityId, "capabilityId");
      this.parameter = parameter;
    }

    public static SmimeCapability parse(JsonMap json) throws CodecException {
      JsonMap map = json.getMap("parameter");
      SmimeCapabilityParameter parameter = (map == null) ? null
          : SmimeCapabilityParameter.parse(map);
      return new SmimeCapability(
          DescribableOid.parseNn(json, "capabilityId"), parameter);
    }

  } // class SmimeCapability

  private static class SmimeCapabilityParameter {

    private final Integer integer;

    private final DescribableBinary binary;

    public SmimeCapabilityParameter(
        Integer integer, DescribableBinary binary) {
      Args.exactOne(integer, "integer", binary, "binary");
      this.integer = integer;
      this.binary  = binary;
    }

    public static SmimeCapabilityParameter parse(JsonMap json)
        throws CodecException {
      DescribableBinary binary = DescribableBinary.parse(json, "binary");
      return new SmimeCapabilityParameter(json.getInt("integer"),
          binary);
    }

  } // class SmimeCapabilityParameter

}
