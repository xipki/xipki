// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.type.Range;
import org.xipki.util.misc.StringUtil;

/**
 * @author Lijun Liao (xipki)
 */
public class RdnControl {

  private final int minOccurs;

  private final int maxOccurs;

  private final ASN1ObjectIdentifier type;

  private TextVadidator pattern;

  private StringType stringType;

  private Range stringLengthRange;

  private String value;

  private GeneralNameTag toSAN;

  public RdnControl(ASN1ObjectIdentifier type) {
    this(type, 1, 1);
  }

  public RdnControl(ASN1ObjectIdentifier type, String value) {
    this.type = Args.notNull(type, "type");
    this.minOccurs = 1;
    this.maxOccurs = 1;
    this.value = StringUtil.isBlank(value) ? null : value;
  }

  public RdnControl(ASN1ObjectIdentifier type, int minOccurs, int maxOccurs) {
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

  public ASN1ObjectIdentifier type() {
    return type;
  }

  public StringType stringType() {
    return stringType;
  }

  public TextVadidator pattern() {
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

  public void setPattern(TextVadidator pattern) {
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
