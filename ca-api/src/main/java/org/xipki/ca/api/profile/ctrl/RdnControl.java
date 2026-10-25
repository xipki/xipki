// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.util.Args;
import org.xipki.ca.api.Range;
import org.xipki.pkix.util.misc.StringUtil;

/**
 * Rdn Control settings.
 *
 * @author Lijun Liao (xipki)
 */
public class RdnControl {

  private final int minOccurs;

  private final int maxOccurs;

  private final Asn1Oid type;

  private TextValidator pattern;

  private StringType stringType;

  private Range stringLengthRange;

  private String value;

  private GeneralNameTag toSAN;

  public RdnControl(Asn1Oid type) {
    this(type, 1, 1);
  }

  public RdnControl(Asn1Oid type, String value) {
    this.type = Args.notNull(type, "type");
    this.minOccurs = 1;
    this.maxOccurs = 1;
    this.value = StringUtil.isBlank(value) ? null : value;
  }

  public RdnControl(Asn1Oid type, int minOccurs, int maxOccurs) {
    if (minOccurs < 0 || maxOccurs < 0 || minOccurs > maxOccurs) {
      throw new IllegalArgumentException(String.format(
          "illegal minOccurs=%s, maxOccurs=%s", minOccurs, maxOccurs));
    }

    this.type = Args.notNull(type, "type");
    this.minOccurs = minOccurs;
    this.maxOccurs = maxOccurs;
  }

  public int minOccurs() {
    return minOccurs;
  }

  public int maxOccurs() {
    return maxOccurs;
  }

  public Asn1Oid type() {
    return type;
  }

  public StringType stringType() {
    return stringType;
  }

  public TextValidator pattern() {
    return pattern;
  }

  public Range stringLengthRange() {
    return stringLengthRange;
  }

  public void setStringType(StringType stringType) {
    this.stringType = stringType;
  }

  public void setStringLengthRange(Range stringLengthRange) {
    this.stringLengthRange = stringLengthRange;
  }

  public void setPattern(TextValidator pattern) {
    this.pattern = pattern;
  }

  public String value() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  public GeneralNameTag toSAN() {
    return toSAN;
  }

  public void setToSAN(GeneralNameTag toSAN) {
    this.toSAN = toSAN;
  }

} // class RdnControl
