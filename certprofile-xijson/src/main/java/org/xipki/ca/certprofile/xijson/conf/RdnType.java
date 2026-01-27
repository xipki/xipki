// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.ca.api.profile.ctrl.RdnControl;
import org.xipki.ca.api.profile.ctrl.StringType;
import org.xipki.ca.api.profile.ctrl.SubjectDnSpec;
import org.xipki.ca.api.profile.ctrl.TextVadidator;
import org.xipki.ca.api.profile.id.AttributeType;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.exception.CertprofileException;

/**
 * @author Lijun Liao (xipki)
 */
public class RdnType implements JsonEncodable {

  private final AttributeType type;

  private Boolean printableString;

  private String regex;

  private final int minOccurs;

  private final int maxOccurs;

  private final String value;

  private GeneralNameTag toSAN;

  public RdnType(AttributeType type) {
    this(type, null, null, null);
  }

  public RdnType(AttributeType type, String value,
                 Integer minOccurs, Integer maxOccurs) {
    this.type = Args.notNull(type, "type");
    this.value = value;

    this.minOccurs = (minOccurs == null) ? 1 : minOccurs;
    this.maxOccurs = (maxOccurs == null) ? 1 : maxOccurs;

    if (this.minOccurs > this.maxOccurs) {
      throw new IllegalArgumentException("minOccurs (" + this.minOccurs +
          ") may not be greater than maxOccurs (" + this.maxOccurs + ")");
    }

    if (value != null) {
      if (this.minOccurs != 1 || this.maxOccurs != 1) {
        throw new IllegalArgumentException(
            "(minOccurs, maxOccurs) is not (1,1), " +
            "but (" + this.minOccurs + "," + this.maxOccurs + ")");
      }
    }
  }

  public AttributeType getType() {
    return type;
  }

  public Boolean getPrintableString() {
    return printableString;
  }

  public void setPrintableString(Boolean printableString) {
    this.printableString = printableString;
  }

  public String getRegex() {
    return regex;
  }

  public void setRegex(String regex) {
    this.regex = regex;
  }

  public int getMinOccurs() {
    return minOccurs;
  }

  public int getMaxOccurs() {
    return maxOccurs;
  }

  public String getValue() {
    return value;
  }

  public void setToSAN(GeneralNameTag toSAN) {
    if (toSAN == null) {
      return;
    }

    if (this.minOccurs > 1) {
      throw new IllegalArgumentException(
          "minOccurs shall be 1, but is " + this.minOccurs);
    }
    this.toSAN = toSAN;
  }

  public GeneralNameTag getToSAN() {
    return toSAN;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("type", type.getMainAlias())
        .put("minOccurs", (minOccurs == 1 ? null : minOccurs))
        .put("maxOccurs", (maxOccurs == 1 ? null : maxOccurs))
        .put("value", value).putEnum("toSAN", toSAN)
        .put("regex", regex).put("printableString", printableString);
  }

  public static RdnType parse(JsonMap json) throws CodecException {
    AttributeType type = AttributeType.ofOidOrName(json.getNnString("type"));
    RdnType ret = new RdnType(type, json.getString("value"),
        json.getInt("minOccurs"), json.getInt("maxOccurs"));

    ret.setToSAN(json.getEnum("toSAN", GeneralNameTag.class));
    ret.setRegex(json.getString("regex"));
    ret.setPrintableString(json.getBool("printableString"));
    return ret;
  }

  public RdnControl toRdnControl() throws CertprofileException {
    RdnControl ret;
    if (value == null) {
        ret = new RdnControl(type.getOid(), minOccurs, maxOccurs);
    } else {
        ret = new RdnControl(type.getOid(), value);
    }

    if (regex != null) {
      ret.setPattern(TextVadidator.compile(regex));
    }

    ret.setToSAN(toSAN);

    if (printableString != null) {
      ret.setStringType(printableString
          ? StringType.utf8String : StringType.printableString);
    }

    SubjectDnSpec.fixRdnControl(ret);
    return ret;
  }

} // class RdnType
