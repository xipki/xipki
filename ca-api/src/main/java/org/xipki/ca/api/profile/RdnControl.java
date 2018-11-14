/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.api.profile;

import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RdnControl {

  private final int minOccurs;

  private final int maxOccurs;

  private final ASN1ObjectIdentifier type;

  private Pattern pattern;

  private StringType stringType;

  private Range stringLengthRange;

  private String prefix;

  private String suffix;

  private String group;

  public RdnControl(ASN1ObjectIdentifier type) {
    this(type, 1, 1);
  }

  public RdnControl(ASN1ObjectIdentifier type, int minOccurs, int maxOccurs) {
    if (minOccurs < 0 || maxOccurs < 1 || minOccurs > maxOccurs) {
      throw new IllegalArgumentException(
          String.format("illegal minOccurs=%s, maxOccurs=%s", minOccurs, maxOccurs));
    }

    this.type = Args.notNull(type, "type");
    this.minOccurs = minOccurs;
    this.maxOccurs = maxOccurs;
  }

  public int getMinOccurs() {
    return minOccurs;
  }

  public int getMaxOccurs() {
    return maxOccurs;
  }

  public ASN1ObjectIdentifier getType() {
    return type;
  }

  public StringType getStringType() {
    return stringType;
  }

  public Pattern getPattern() {
    return pattern;
  }

  public Range getStringLengthRange() {
    return stringLengthRange;
  }

  public void setStringType(StringType stringType) {
    this.stringType = stringType;
  }

  public void setStringLengthRange(Range stringLengthRange) {
    this.stringLengthRange = stringLengthRange;
  }

  public void setPattern(Pattern pattern) {
    this.pattern = pattern;
  }

  public String getPrefix() {
    return prefix;
  }

  public void setPrefix(String prefix) {
    this.prefix = prefix;
  }

  public String getSuffix() {
    return suffix;
  }

  public void setSuffix(String suffix) {
    this.suffix = suffix;
  }

  public String getGroup() {
    return group;
  }

  public void setGroup(String group) {
    this.group = group;
  }

}
