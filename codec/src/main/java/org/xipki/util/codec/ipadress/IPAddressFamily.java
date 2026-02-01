// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.codec.ipadress;

import org.xipki.util.codec.Args;

/**
 * A list of AFI is available under
 * https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml.
 *
 * A list of SAFI is available under
 * https://www.iana.org/assignments/safi-namespace/safi-namespace.xhtml
 *
 * @author Lijun Liao (xipki)
 */
public class IPAddressFamily {

  public static final int AFI_IPv4 = 1;

  public static final int AFI_IPv6 = 2;

  public static final int AFI_NSAP = 3;

  public static final int AFI_HDLC = 4;

  public static final int AFI_BBN_1822 = 5;

  public static final int AFI_IEEE_802 = 6;

  public static final int AFI_E_163 = 7;

  public static final int AFI_E_164 = 8;

  public static final int AFI_F_69 = 9;

  public static final int AFI_X_121 = 10;

  public static final int AFI_IPX = 11;

  public static final int AFI_Appletalk = 12;

  public static final int AFI_Decnet_IV = 13;

  public static final int AFI_Banyan_Vines = 14;

  public static final int AFI_E_164_NSAP_subaddress = 15;

  public static final int AFI_DNS = 16;

  public static final byte SAFI_unicast = 1;
  public static final byte SAFI_multicast = 2;

  private final int afi;

  private final Byte safi;

  public IPAddressFamily(int afi, Byte safi) {
    this.afi = Args.among(afi, "afi", 0, 0xFFFF);
    this.safi = safi;
  }

  public IPAddressFamily(byte[] encoded) {
    int len = encoded.length;
    if (len == 2 || len == 3) {
      this.afi = ((0xFF & encoded[0]) << 8) | ((0xFF & encoded[1]));
      this.safi = (len == 3) ? encoded[2] : null;
    } else {
      throw new IllegalArgumentException("invalid encoded.length: " + len);
    }
  }

  public int afi() {
    return afi;
  }

  @Override
  public String toString() {
    String afiString;
    switch (afi) {
      case AFI_IPv4:
        afiString = "IPv4";
        break;
      case AFI_IPv6:
        afiString = "IPv6";
        break;
      case AFI_NSAP:
        afiString = "NSAP";
        break;
      case AFI_HDLC:
        afiString = "HDLC";
        break;
      case AFI_BBN_1822:
        afiString = "BBN.1822";
        break;
      case AFI_IEEE_802:
        afiString = "IEEE.802";
        break;
      case AFI_E_163:
        afiString = "E.163";
        break;
      case AFI_E_164:
        afiString = "E.164";
        break;
      case AFI_F_69:
        afiString = "F.69";
        break;
      case AFI_X_121:
        afiString = "X.121";
        break;
      case AFI_IPX:
        afiString = "IPX";
        break;
      case AFI_Appletalk:
        afiString = "Appletalk";
        break;
      case AFI_Decnet_IV:
        afiString = "Decnet IV";
        break;
      case AFI_Banyan_Vines:
        afiString = "Banyan Vines";
        break;
      case AFI_E_164_NSAP_subaddress:
        afiString = "E.164 NSAP subaddress";
        break;
      case AFI_DNS:
        afiString = "DNS";
        break;
      default:
        afiString = Integer.toString(afi);
    }

    String safiString = "";
    if (safi != null) {
      switch (safi) {
        case SAFI_unicast:
          safiString = " unicast";
          break;
        case SAFI_multicast:
          safiString = " multicast";
          break;
        default:
          safiString = " " + (0xFF & safi);
      }
    }

    return afiString + safiString;
  }

}
