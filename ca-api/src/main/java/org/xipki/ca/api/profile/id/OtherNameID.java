// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.id;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.SpdmOIDs;
import org.xipki.codec.asn1.oid.TcgOIDs;
import org.xipki.codec.asn1.oid.X509OIDs;
import org.xipki.codec.util.Args;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * OtherName Type definition.
 *
 * @author Lijun Liao (xipki)
 */
public class OtherNameID extends AbstractID {

  private static final Map<String, OtherNameID> typeMap = new HashMap<>();

  public static final OtherNameID DMTF_device_info =
      initOf(SpdmOIDs.id_DMTF_device_info, "DMTF-device-info");

  public static final OtherNameID tcg_platformIdentifier =
      initOf(TcgOIDs.tcg_at_platformIdentifier, "TCG-platformIdentifier");

  public static final OtherNameID hardwareModuleName =
      initOf(X509OIDs.id_on_hardwareModuleName, "HardwareModuleName");

  public static final OtherNameID smtpUTF8Mailbox =
      initOf(X509OIDs.id_on_SmtpUTF8Mailbox, "SmtpUTF8Mailbox");

  public static final OtherNameID macAddress =
      initOf(X509OIDs.id_on_MACAddress, "MACAddress");

  private OtherNameID(Asn1Oid x509, List<String> aliases) {
    super(x509, aliases);
  }

  private static OtherNameID initOf(Asn1Oid oid, String alias) {
    Args.notNull(oid, "oid");
    List<String> l = new ArrayList<>();
    l.add(alias);
    l.add(oid.getId());
    return addToMap(new OtherNameID(oid, l), typeMap);
  }

  public static OtherNameID ofOid(Asn1Oid oid) {
    Args.notNull(oid, "oid");
    OtherNameID attr = ofOidOrName(typeMap, oid.getId());
    if (attr != null) {
      return attr;
    }

    return new OtherNameID(oid, Collections.singletonList(oid.getId()));
  }

  public static OtherNameID ofOidOrName(String oidOrName) {
    String c14n = canonicalizeAlias(Args.notNull(oidOrName, "oidOrName"));
    OtherNameID id = ofOidOrName(typeMap, c14n);
    if (id != null) {
      return id;
    }

    try {
      Asn1Oid oid = new Asn1Oid(c14n);
      return new OtherNameID(oid, Collections.singletonList(oid.getId()));
    } catch (RuntimeException e) {
      return null;
    }
  }

}
