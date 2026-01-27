// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.scep.message;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.HashAlgo;
import org.xipki.security.scep.transaction.CaCapability;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.misc.StringUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;

import static org.xipki.security.scep.transaction.CaCapability.AES;
import static org.xipki.security.scep.transaction.CaCapability.DES3;
import static org.xipki.security.scep.transaction.CaCapability.GetNextCACert;
import static org.xipki.security.scep.transaction.CaCapability.POSTPKIOperation;
import static org.xipki.security.scep.transaction.CaCapability.Renewal;
import static org.xipki.security.scep.transaction.CaCapability.SCEPStandard;
import static org.xipki.security.scep.transaction.CaCapability.SHA1;
import static org.xipki.security.scep.transaction.CaCapability.SHA256;
import static org.xipki.security.scep.transaction.CaCapability.SHA512;

/**
 * CA caps.
 *
 * @author Lijun Liao (xipki)
 */

public class CaCaps {

  private static final Logger LOG = LoggerFactory.getLogger(CaCaps.class);

  private byte[] bytes;

  private final Set<CaCapability> capabilities;

  public CaCaps() {
    this.capabilities = new HashSet<>();
  }

  public CaCaps(Set<CaCapability> capabilities) {
    this.capabilities = CollectionUtil.isEmpty(capabilities)
        ? new HashSet<>() : new HashSet<>(capabilities);
    refresh();
  }

  public Set<CaCapability> capabilities() {
    return Collections.unmodifiableSet(capabilities);
  }

  public void addCapabilities(CaCapability... caps) {
    Args.notNull(caps, "caps");
    Collections.addAll(capabilities, caps);
    refresh();
  }

  public void removeCapabilities(CaCaps caCaps) {
    Args.notNull(caCaps, "caCaps");
    this.capabilities.retainAll(caCaps.capabilities);
    refresh();
  }

  public void removeCapabilities(CaCapability... caps) {
    Args.notNull(caps, "caps");
    for (CaCapability m : caps) {
      capabilities.remove(m);
    }
    refresh();
  }

  private boolean containsCapability(CaCapability cap) {
    Args.notNull(cap, "cap");
    return capabilities.contains(cap);
  }

  public boolean supportsSHA1() {
    return containsCapability(SHA1);
  }

  public boolean supportsSHA512() {
    return containsCapability(SHA512);
  }

  public boolean supportsSHA256() {
    return containsCapability(SHA256) || containsCapability(SCEPStandard);
  }

  public boolean supportsAES() {
    return containsCapability(AES) || containsCapability(SCEPStandard);
  }

  public boolean supportsDES3() {
    return containsCapability(DES3);
  }

  public boolean supportsRenewal() {
    return containsCapability(Renewal);
  }

  public boolean supportsGetNextCACert() {
    return containsCapability(GetNextCACert);
  }

  @Override
  public String toString() {
    return toScepMessage();
  }

  @Override
  public int hashCode() {
    return toScepMessage().hashCode();
  }

  public String toScepMessage() {
    if (capabilities.isEmpty()) {
      return "";
    }

    StringBuilder sb = new StringBuilder();
    for (CaCapability cap : capabilities) {
      sb.append(cap.getText()).append("\n");
    }
    sb.deleteCharAt(sb.length() - 1);
    return sb.toString();
  }

  public boolean supportsPost() {
    return containsCapability(POSTPKIOperation)
        || containsCapability(SCEPStandard);
  }

  public HashAlgo mostSecureHashAlgo() {
    return supportsSHA512() ? HashAlgo.SHA512
        : supportsSHA256() ? HashAlgo.SHA256 : HashAlgo.SHA1;
  }

  private void refresh() {
    if (capabilities != null) {
      this.bytes = StringUtil.toUtf8Bytes(toString());
    }
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof CaCaps)) {
      return false;
    }

    return capabilities.equals(((CaCaps) obj).capabilities);
  }

  public byte[] getBytes() {
    return Arrays.copyOf(bytes, bytes.length);
  }

  public static CaCaps getInstance(String scepMessage) {
    CaCaps ret = new CaCaps();
    if (StringUtil.isBlank(scepMessage)) {
      return ret;
    }

    StringTokenizer st = new StringTokenizer(scepMessage, "\r\n");

    List<CaCapability> caps = new ArrayList<>(st.countTokens());
    while (st.hasMoreTokens()) {
      String token = st.nextToken();
      try {
        caps.add(CaCapability.forValue(token));
      } catch (IllegalArgumentException ex) {
        LOG.warn("ignore unknown CACap '{}'", token);
      }
    }

    if (!caps.isEmpty()) {
      ret.addCapabilities(caps.toArray(new CaCapability[0]));
    }

    return ret;
  }

}
