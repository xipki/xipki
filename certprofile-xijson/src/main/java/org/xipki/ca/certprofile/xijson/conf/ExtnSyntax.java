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

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.xipki.security.X509ExtensionType.FieldType;
import org.xipki.security.X509ExtensionType.Tag;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.InvalidConfException;
import org.xipki.util.StringUtil;

import com.alibaba.fastjson.annotation.JSONField;

public class ExtnSyntax extends Describable {

  @JSONField(ordinal = 1)
  private FieldType type;

  /**
   * Will be considered if the type is one of TeletexString, PrintableString, UTF8String and
   * BMPString.
   */
  @JSONField(ordinal = 3)
  private String stringRegex;

  @JSONField(ordinal = 4)
  private Tag tag;

  @JSONField(ordinal = 5)
  private List<SubFieldSyntax> subFields;

  @JSONField(name = "type")
  public String getTypeText() {
    return type.getText();
  }

  // for the JSON deserializer
  private ExtnSyntax() {
  }

  public ExtnSyntax(FieldType type) {
    this.type = Args.notNull(type, "type");
  }

  @JSONField(name = "type")
  public void setTypeText(String text) {
    if (text == null) {
      this.type = null;
    } else {
      this.type = null;
      for (FieldType m : FieldType.values()) {
        if (m.name().equalsIgnoreCase(text) || m.getText().equalsIgnoreCase(text)) {
          this.type = m;
        }
      }

      if (type == null) {
        throw new IllegalArgumentException("invalid type " + type);
      }
    }
  } // method setTypeText

  public FieldType type() {
    return type;
  }

  public Tag getTag() {
    return tag;
  }

  public void setTag(Tag tag) {
    this.tag = tag;
  }

  public String getStringRegex() {
    return stringRegex;
  }

  public void setStringRegex(String stringRegex) {
    if (StringUtil.isNotBlank(stringRegex)) {
      this.stringRegex = stringRegex;
    } else {
      this.stringRegex = null;
    }
  } // method setStringRegex

  public List<SubFieldSyntax> getSubFields() {
    return subFields;
  }

  public void setSubFields(List<SubFieldSyntax> subFields) {
    this.subFields = subFields;
  }

  @Override
  public void validate()
      throws InvalidConfException {
    notNull(type, "type");
    if (CollectionUtil.isNotEmpty(subFields)) {
      if (type == FieldType.SEQUENCE || type == FieldType.SET) {
        for (SubFieldSyntax m : subFields) {
          m.validate();
        }
      } else if (type == FieldType.SEQUENCE_OF || type == FieldType.SET_OF) {
        // the fields will be considered as the subfields of CHOICE, make sure that
        // two subfields of same type have different tag
        Set<String> set = new HashSet<>();
        for (SubFieldSyntax m : subFields) {
          if (m.isRequired()) {
            throw new InvalidConfException(
                "SubField within SEQUECE_OF or SET OF must not be required");
          }

          int tag = (m.getTag() != null) ? m.getTag().getValue() : -1;
          if (!set.add(m.type() + "-" + tag)) {
            throw new InvalidConfException("multiple " + m.type()
                + " of the same tag (or no tag) within " + type + " defined");
          }

          m.validate();
        }
      } else {
        throw new InvalidConfException("unsupported type " + type);
      }
    }
  } // method validate

  public static class SubFieldSyntax extends ExtnSyntax {

    private boolean required;

    // for the JSON deserializer
    @SuppressWarnings("unused")
    private SubFieldSyntax() {
    }

    public SubFieldSyntax(FieldType type) {
      super(type);
    }

    public boolean isRequired() {
      return required;
    }

    public void setRequired(boolean required) {
      this.required = required;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      super.validate();
      if (FieldType.RAW == type()) {
        throw new InvalidConfException("FieldType RAW is not allowed");
      }
    }

  } // class SubFieldSyntax

} // class ExtnSyntax
