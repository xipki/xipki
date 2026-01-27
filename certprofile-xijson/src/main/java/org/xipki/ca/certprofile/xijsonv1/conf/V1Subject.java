// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.profile.id.AttributeType;
import org.xipki.ca.certprofile.xijson.conf.RdnType;
import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableOid;
import org.xipki.ca.certprofile.xijsonv1.conf.type.V1StringType;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration of the certificate's subject field.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class V1Subject {

  private static final Logger LOG = LoggerFactory.getLogger(V1Subject.class);

  /**
   * whether the RDNs occurs as in the defined ASN.1 order.
   */
  private final Boolean keepRdnOrder;

  private final List<V1RdnType> rdns;

  public V1Subject(Boolean keepRdnOrder, List<V1RdnType> rdns) {
    this.keepRdnOrder = keepRdnOrder;
    this.rdns = Args.notEmpty(rdns, "rdns");
  }

  // do not encode the default value.
  public Boolean getKeepRdnOrder() {
    return keepRdnOrder;
  }

  public List<V1RdnType> getRdns() {
    return rdns;
  }

  public static V1Subject parse(JsonMap json) throws CodecException {
    JsonList list = json.getNnList("rdns");
    List<V1RdnType> rdns = (list == null) ? null : V1RdnType.parseList(list);
    return new V1Subject(json.getBool("keepRdnOrder"), rdns);
  }

  public static class ValueType {

    private final String text;

    /**
     * Whether the value can be overridden by the request.
     */
    private final boolean overridable;

    public ValueType(String text, boolean overridable) {
      this.text = Args.notBlank(text, "text");
      this.overridable = overridable;
    }

    public String getText() {
      return text;
    }

    public boolean isOverridable() {
      return overridable;
    }

    public static ValueType parse(JsonMap json) throws CodecException {
      return new ValueType(json.getNnString("text"),
          json.getBool("overridable", false));
    }

  }

  public static class V1RdnType {

    private final DescribableOid type;

    private V1StringType stringType;

    private String regex;

    private String prefix;

    private String suffix;

    private Integer minOccurs;

    private Integer maxOccurs;

    private String group;

    private ValueType value;

    public V1RdnType(DescribableOid type) {
      this.type = Args.notNull(type, "type");
    }

    public RdnType toV2() {
      AttributeType v2Type = AttributeType.ofOid(type.oid());

      String v2Value = null;
      if (value != null) {
        if (value.isOverridable()) {
          LOG.warn("ignore RdnType.overridable=true");
        }
        v2Value = value.getText();
      }

      if (group != null) {
        throw new IllegalArgumentException("RDN.group is not supported");
      }

      if (prefix != null && !prefix.isEmpty()) {
        throw new IllegalArgumentException("RDN.prefix is not supported");
      }

      if (suffix != null && !suffix.isEmpty()) {
        throw new IllegalArgumentException("RDN.suffix is not supported");
      }

      Boolean v2PrintableString = null;
      if (stringType != null) {
        if (stringType == V1StringType.printableString) {
          v2PrintableString = true;
        }
      }

      RdnType ret = new RdnType(v2Type, v2Value, minOccurs, maxOccurs);
      ret.setPrintableString(v2PrintableString);
      ret.setRegex(regex);
      return ret;
    }

    public static List<V1RdnType> parseList(JsonList list)
        throws CodecException {
      List<V1RdnType> ret = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        ret.add(V1RdnType.parse(v));
      }
      return ret;
    }

    public static V1RdnType parse(JsonMap json) throws CodecException {
      V1RdnType ret = new V1RdnType(DescribableOid.parseNn(json, "type"));

      ret.stringType = json.getEnum("stringType", V1StringType.class);
      ret.regex  = json.getString("regex");
      ret.prefix = json.getString("prefix");
      ret.suffix = json.getString("suffix");
      ret.minOccurs = json.getInt("minOccurs");
      ret.maxOccurs = json.getInt("maxOccurs");
      ret.group = json.getString("group");

      JsonMap map = json.getMap("value");
      if (map != null) {
        ret.value = ValueType.parse(map);
      }

      return ret;
    }
  }

}

