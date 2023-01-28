/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.certprofile.xijson.conf;

import com.alibaba.fastjson.annotation.JSONField;
import org.xipki.ca.api.profile.Certprofile.StringType;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.LinkedList;
import java.util.List;

/**
 * Configuration of the certificate's subject field.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Subject extends ValidatableConf {

  /**
   * whether the RDNs occurs as in the defined ASN.1 order.
   */
  @JSONField(ordinal = 2)
  private Boolean keepRdnOrder;

  @JSONField(ordinal = 3)
  private List<RdnType> rdns;

  // do not encode the default value.
  public Boolean getKeepRdnOrder() {
    return keepRdnOrder != null && keepRdnOrder ? Boolean.TRUE :null;
  }

  public void setKeepRdnOrder(Boolean keepRdnOrder) {
    this.keepRdnOrder = keepRdnOrder;
  }

  public boolean keepRdnOrder() {
    return keepRdnOrder != null && keepRdnOrder;
  }

  public List<RdnType> getRdns() {
    if (rdns == null) {
      rdns = new LinkedList<>();
    }
    return rdns;
  }

  public void setRdns(List<RdnType> rdns) {
    this.rdns = rdns;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(rdns, "rdns");
    validate(rdns);
  }

  public static class ValueType extends ValidatableConf {

    private String text;

    /**
     * Whether the value can be overridden by the request.
     */
    private boolean overridable;

    public String getText() {
      return text;
    }

    public void setText(String text) {
      this.text = text;
    }

    public boolean isOverridable() {
      return overridable;
    }

    public void setOverridable(boolean overridable) {
      this.overridable = overridable;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(text, "text");
    }

  } // class ValueType

  public static class RdnType extends ValidatableConf {

    @JSONField(ordinal = 1)
    private DescribableOid type;

    @JSONField(ordinal = 2)
    private Integer minLen;

    @JSONField(ordinal = 3)
    private Integer maxLen;

    @JSONField(ordinal = 4)
    private StringType stringType;

    @JSONField(ordinal = 5)
    private String regex;

    @JSONField(ordinal = 6)
    private String prefix;

    @JSONField(ordinal = 7)
    private String suffix;

    @JSONField(ordinal = 8)
    private Integer minOccurs;

    @JSONField(ordinal = 9)
    private Integer maxOccurs;

    @JSONField(ordinal = 10)
    private String group;

    /**
     * This RDN is for other purpose, will not be contained in the Subject field of certificate.
     */
    @JSONField(ordinal = 11)
    private Boolean notInSubject;

    @JSONField(ordinal = 11)
    private ValueType value;

    public DescribableOid getType() {
      return type;
    }

    public void setType(DescribableOid type) {
      this.type = type;
    }

    public Integer getMinLen() {
      return minLen;
    }

    public void setMinLen(Integer minLen) {
      this.minLen = minLen;
    }

    public int minLen() {
      return minLen == null ? 1 : minLen;
    }

    public Integer getMaxLen() {
      return maxLen;
    }

    public void setMaxLen(Integer maxLen) {
      this.maxLen = maxLen;
    }

    public int maxLen() {
      return maxLen == null ? 1 : maxLen;
    }

    public StringType getStringType() {
      return stringType;
    }

    public void setStringType(StringType stringType) {
      this.stringType = stringType;
    }

    public String getRegex() {
      return regex;
    }

    public void setRegex(String regex) {
      this.regex = regex;
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

    public int minOccurs() {
      return minOccurs == null ? 1 : minOccurs;
    }

    public int maxOccurs() {
      return maxOccurs == null ? 1 : maxOccurs;
    }

    // do not encode the default value.
    public Integer getMinOccurs() {
      return minOccurs != null && minOccurs == 1 ? null : minOccurs;
    }

    public void setMinOccurs(Integer minOccurs) {
      this.minOccurs = minOccurs;
    }

    // do not encode the default value.
    public Integer getMaxOccurs() {
      return maxOccurs != null && maxOccurs == 1 ? null : maxOccurs;
    }

    public void setMaxOccurs(Integer maxOccurs) {
      this.maxOccurs = maxOccurs;
    }

    public String getGroup() {
      return group;
    }

    public void setGroup(String group) {
      this.group = group;
    }

    public ValueType getValue() {
      return value;
    }

    public void setValue(ValueType value) {
      this.value = value;
    }

    public Boolean getNotInSubject() {
      return notInSubject;
    }

    public void setNotInSubject(Boolean notInSubject) {
      this.notInSubject = notInSubject;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(type, "type");
      validate(type);

      int minOccurs = minOccurs();
      int maxOccurs = maxOccurs();

      if (minOccurs > maxOccurs) {
        throw new InvalidConfException(
            "minOccurs (" + minOccurs + ") may not be greater than maxOccurs (" + maxOccurs + ")");
      }

      if (value != null) {
        if (minOccurs != 1 || maxOccurs != 1) {
          throw new InvalidConfException(
              "(minOccurs, maxOccurs) is not (1,1), but (" + minOccurs + "," + maxOccurs + ")");
        }

        value.validate();
      }
    } // method validate

  } // class RdnType

}

