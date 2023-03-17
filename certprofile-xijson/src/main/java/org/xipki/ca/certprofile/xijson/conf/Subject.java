// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

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
  private Boolean keepRdnOrder;

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

    private DescribableOid type;

    private Integer minLen;

    private Integer maxLen;

    private StringType stringType;

    private String regex;

    private String prefix;

    private String suffix;

    private Integer minOccurs;

    private Integer maxOccurs;

    private String group;

    /**
     * This RDN is for other purpose, will not be contained in the Subject field of certificate.
     */
    private Boolean notInSubject;

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

