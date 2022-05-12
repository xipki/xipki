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

package org.xipki.ca.api.mgmt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.StringUtil;

import java.util.Set;
import java.util.StringTokenizer;

/**
 * Protocol support control (e.g. CMP, REST and SCEP).
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ProtocolSupport {

  private static final Logger LOG = LoggerFactory.getLogger(ProtocolSupport.class);

  private static final String CMP = "cmp";

  private static final String REST = "rest";

  private static final String SCEP = "scep";

  private boolean cmp;

  private boolean rest;

  private boolean scep;

  // For the deserialization only
  @SuppressWarnings("unused")
  private ProtocolSupport() {
  }

  public ProtocolSupport(Set<String> protocols) {
    if (protocols == null) {
      return;
    }

    for (String protocol : protocols) {
      protocol = protocol.toLowerCase();
      switch (protocol) {
        case CMP:
          cmp = true;
          break;
        case REST:
          rest = true;
          break;
        case SCEP:
          scep = true;
          break;
        default:
          LOG.warn("unknown protocol {}", protocol);
      }
    }
  }

  public ProtocolSupport(String encoded) {
    if (StringUtil.isBlank(encoded)) {
      return;
    }

    StringTokenizer st = new StringTokenizer(encoded, ",");
    while (st.hasMoreTokens()) {
      String protocol = st.nextToken().toLowerCase();
      switch (protocol) {
        case CMP:
          cmp = true;
          break;
        case REST:
          rest = true;
          break;
        case SCEP:
          scep = true;
          break;
        default:
          LOG.warn("unknown protocol {}", protocol);
      }
    }
  } // constructor

  public ProtocolSupport(boolean cmp, boolean rest, boolean scep) {
    this.cmp = cmp;
    this.rest = rest;
    this.scep = scep;
  }

  public boolean isCmp() {
    return cmp;
  }

  public void setCmp(boolean cmp) {
    this.cmp = cmp;
  }

  public boolean isRest() {
    return rest;
  }

  public void setRest(boolean rest) {
    this.rest = rest;
  }

  public boolean isScep() {
    return scep;
  }

  public void setScep(boolean scep) {
    this.scep = scep;
  }

  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (! (obj instanceof ProtocolSupport)) {
      return false;
    }

    ProtocolSupport other = (ProtocolSupport) obj;
    return cmp == other.cmp
        && rest == other.rest
        && scep == other.scep;
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("supported protocols: ")
        .append(cmp ? "" : "CMP, ")
        .append(rest ? "" : "REST, ")
        .append(scep ? "" : "SCEP, ");
    if (cmp || rest || scep) {
      sb.delete(sb.length() - 2, sb.length());
    }
    return sb.toString();
  }

  public String getEncoded() {
    StringBuilder st = new StringBuilder(15);
    if (cmp) {
      st.append(CMP).append(",");
    }

    if (rest) {
      st.append(REST).append(",");
    }

    if (scep) {
      st.append(SCEP).append(",");
    }

    return st.length() == 0  ? "" : st.deleteCharAt(st.length() - 1).toString();
  }

}
