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

package org.xipki.ca.mgmt.api;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.InvalidConfException;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;
import org.xipki.util.TripleState;

/**
 *<pre>
 * Example configuration
 * update.mode=&lt;'interval'|'ondemand'&gt;
 *
 * # For all updateMode
 *
 * # Whether expired certificates are considered. Default is false
 * expiredcerts.included=&lt;'true'|'false'&gt;
 *
 * # Whether XiPKI-customized extension xipki-CrlCertSet is included. Default is false
 * xipki.certset=&lt;'true'|'false'&gt;
 *
 * # Whether the extension xipki-CrlCertSet contains the raw certificates. Default is true
 * xipki.certset.certs=&lt;'true'|'false'&gt;
 *
 * # Whether the extension xipki-CrlCertSet contains the profile name of the certificate.
 * # Default is true
 * xipki.certset.profilename=&lt;'true'|'false'&gt;
 *
 * # List of OIDs of extensions to be embedded in CRL,
 * # Unspecified or empty extensions indicates that the CA decides.
 * extensions=&lt;comma delimited OIDs of extensions&gt;
 *
 * # The following settings are only for updateMode 'interval'
 *
 * # Number of intervals to generate a full CRL. Default is 1
 * # Should be greater than 0
 * fullcrl.intervals=&lt;integer&gt;
 *
 * # should be 0 or not greater than baseCRL.intervals. Default is 0.
 * # 0 indicates that no deltaCRL will be generated
 * deltacrl.intervals=&lt;integer&gt;
 *
 * overlap.minutes=&lt;minutes of overlap&gt;
 *
 * # should be less than fullCRL.intervals.
 * # If activated, a deltaCRL will be generated only between two full CRLs
 * deltacrl.intervals=&lt;integer&gt;
 *
 * # Exactly one of interval.minutes and interval.days should be specified
 * # Number of minutes of one interval. At least 60 minutes
 * interval.minutes=&lt;minutes of one interval&gt;
 *
 * # UTC time of generation of CRL, one interval covers 1 day.
 * interval.time=&lt;updatet time (hh:mm of UTC time)&gt;
 *
 * # Whether the nextUpdate of a fullCRL is the update time of the fullCRL
 * # Default is false
 * fullcrl.extended.nextupdate=&lt;'true'|'false'&gt;
 *
 * # Whether only user certificates are considered in CRL
 * # Default is false
 * user.certs.only=&lt;'true'|'false'&gt;
 *
 * # Whether only CA certificates are considered in CRL
 * # Default if false
 * ca.certs.only=&lt;'true'|'false'&gt;
 *
 * # Whether Revocation reason is contained in CRL
 * # Default is false
 * exclude.reason=&lt;'true'|'false'&gt;
 *
 * # How the CRL entry extension invalidityDate is considered in CRL
 * # Default is false
 * invalidity.date=&lt;'required'|'optional'|'forbidden'&gt;
 *
 * </pre>
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CrlControl {

  public enum UpdateMode {

    INTERVAL("interval"),
    ONDEMAND("ondemand");

    private String mode;

    private UpdateMode(String mode) {
      this.mode = mode;
    }

    public static UpdateMode forName(String mode) {
      Args.notNull(mode, "mode");
      for (UpdateMode v : values()) {
        if (v.mode.equalsIgnoreCase(mode)) {
          return v;
        }
      }

      throw new IllegalArgumentException("invalid UpdateMode '" + mode + "'");
    }

  } // enum UpdateMode

  public static class HourMinute {

    private final int hour;

    private final int minute;

    public HourMinute(int hour, int minute) {
      this.hour = Args.range(hour, "hour", 0, 23);
      this.minute = Args.range(minute, "minute", 0, 59);
    }

    public int getHour() {
      return hour;
    }

    public int getMinute() {
      return minute;
    }

    @Override
    public String toString() {
      return StringUtil.concatObjectsCap(100, (hour < 10 ? "0" : ""), hour, ":",
          (minute < 10 ? "0" : ""), minute);
    }

    @Override
    public int hashCode() {
      return toString().hashCode();
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      } else if (!(obj instanceof HourMinute)) {
        return false;
      }

      HourMinute hm = (HourMinute) obj;
      return hour == hm.hour && minute == hm.minute;
    }

  } // class HourMinute

  public static final String KEY_UPDATE_MODE = "update.mode";

  public static final String KEY_EYTENSIONS = "extensions";

  public static final String KEY_EXPIRED_CERTS_INCLUDED = "expiredcerts.included";

  public static final String KEY_XIPKI_CERTSET = "xipki.certset";

  public static final String KEY_XIPKI_CERTSET_CERTS = "xipki.certset.certs";

  public static final String KEY_FULLCRL_INTERVALS = "fullcrl.intervals";

  public static final String KEY_DELTACRL_INTERVALS = "deltacrl.intervals";

  public static final String KEY_OVERLAP_MINUTES = "overlap.minutes";

  public static final String KEY_INTERVAL_MINUTES = "interval.minutes";

  public static final String KEY_INTERVAL_TIME = "interval.time";

  public static final String KEY_FULLCRL_EXTENDED_NEXTUPDATE = "fullcrl.extended.nextupdate";

  public static final String KEY_ONLY_CONTAINS_USERCERTS = "user.certs.only";

  public static final String KEY_ONLY_CONTAINS_CACERTS = "ca.certs.only";

  public static final String KEY_EXCLUDE_REASON = "exclude.reason";

  public static final String KEY_INVALIDITY_DATE = "invalidity.date";

  private UpdateMode updateMode = UpdateMode.INTERVAL;

  private boolean xipkiCertsetIncluded;

  private boolean xipkiCertsetCertIncluded = true;

  private boolean includeExpiredCerts;

  private int fullCrlIntervals = 1;

  private int deltaCrlIntervals;

  private int overlapMinutes = 10;

  private boolean extendedNextUpdate;

  private Integer intervalMinutes;

  private HourMinute intervalDayTime;

  private boolean onlyContainsUserCerts;

  private boolean onlyContainsCaCerts;

  private boolean excludeReason;

  private TripleState invalidityDateMode = TripleState.OPTIONAL;

  private final Set<String> extensionOids;

  public CrlControl(String conf) throws InvalidConfException {
    ConfPairs props;
    try {
      props = new ConfPairs(conf);
    } catch (RuntimeException ex) {
      throw new InvalidConfException(ex.getClass().getName() + ": " + ex.getMessage(), ex);
    }

    String str = props.value(KEY_UPDATE_MODE);
    this.updateMode = (str == null) ? UpdateMode.INTERVAL : UpdateMode.forName(str);

    str = props.value(KEY_INVALIDITY_DATE);
    if (str != null) {
      this.invalidityDateMode = TripleState.forValue(str);
    }

    this.includeExpiredCerts = getBoolean(props, KEY_EXPIRED_CERTS_INCLUDED, false);

    this.xipkiCertsetIncluded = getBoolean(props, KEY_XIPKI_CERTSET, false);

    this.xipkiCertsetCertIncluded = getBoolean(props, KEY_XIPKI_CERTSET_CERTS, true);

    str = props.value(KEY_EYTENSIONS);
    if (str == null) {
      this.extensionOids = Collections.emptySet();
    } else {
      Set<String> oids = StringUtil.splitAsSet(str, ", ");
      // check the OID
      for (String oid : oids) {
        try {
          new ASN1ObjectIdentifier(oid);
        } catch (IllegalArgumentException ex) {
          throw new InvalidConfException(oid + " is not a valid OID");
        }
      }
      this.extensionOids = oids;
    }

    this.onlyContainsCaCerts = getBoolean(props, KEY_ONLY_CONTAINS_CACERTS, false);
    this.onlyContainsUserCerts = getBoolean(props, KEY_ONLY_CONTAINS_USERCERTS, false);
    this.excludeReason = getBoolean(props, KEY_EXCLUDE_REASON, false);

    if (this.updateMode != UpdateMode.ONDEMAND) {
      this.fullCrlIntervals = getInteger(props, KEY_FULLCRL_INTERVALS, 1);
      this.deltaCrlIntervals = getInteger(props, KEY_DELTACRL_INTERVALS, 0);
      this.extendedNextUpdate = getBoolean(props, KEY_FULLCRL_EXTENDED_NEXTUPDATE, false);
      this.overlapMinutes = getInteger(props, KEY_OVERLAP_MINUTES, 60);
      str = props.value(KEY_INTERVAL_TIME);
      if (str != null) {
        List<String> tokens = StringUtil.split(str.trim(), ":");
        if (tokens.size() != 2) {
          throw new InvalidConfException(
              "invalid " + KEY_INTERVAL_TIME + ": '" + str + "'");
        }

        try {
          int hour = Integer.parseInt(tokens.get(0));
          int minute = Integer.parseInt(tokens.get(1));
          this.intervalDayTime = new HourMinute(hour, minute);
        } catch (IllegalArgumentException ex) {
          throw new InvalidConfException("invalid " + KEY_INTERVAL_TIME + ": '" + str + "'");
        }
      } else {
        int minutes = getInteger(props, KEY_INTERVAL_MINUTES, 0);
        if (minutes < this.overlapMinutes + 30) {
          throw new InvalidConfException("invalid " + KEY_INTERVAL_MINUTES + ": '"
              + minutes + " is less than than 30 + " + this.overlapMinutes);
        }
        this.intervalMinutes = minutes;
      }
    }

    validate();
  } // constructor

  public String getConf() {
    ConfPairs pairs = new ConfPairs();
    pairs.putPair(KEY_UPDATE_MODE, updateMode.name());
    pairs.putPair(KEY_EXPIRED_CERTS_INCLUDED, Boolean.toString(includeExpiredCerts));
    pairs.putPair(KEY_XIPKI_CERTSET, Boolean.toString(xipkiCertsetIncluded));
    pairs.putPair(KEY_XIPKI_CERTSET_CERTS, Boolean.toString(xipkiCertsetCertIncluded));
    pairs.putPair(KEY_XIPKI_CERTSET, Boolean.toString(xipkiCertsetIncluded));
    pairs.putPair(KEY_ONLY_CONTAINS_CACERTS, Boolean.toString(onlyContainsCaCerts));
    pairs.putPair(KEY_ONLY_CONTAINS_USERCERTS, Boolean.toString(onlyContainsUserCerts));
    pairs.putPair(KEY_EXCLUDE_REASON, Boolean.toString(excludeReason));
    pairs.putPair(KEY_INVALIDITY_DATE, invalidityDateMode.name());
    if (updateMode != UpdateMode.ONDEMAND) {
      pairs.putPair(KEY_FULLCRL_INTERVALS, Integer.toString(fullCrlIntervals));
      pairs.putPair(KEY_FULLCRL_EXTENDED_NEXTUPDATE, Boolean.toString(extendedNextUpdate));
      pairs.putPair(KEY_DELTACRL_INTERVALS, Integer.toString(deltaCrlIntervals));

      if (intervalDayTime != null) {
        pairs.putPair(KEY_INTERVAL_TIME, intervalDayTime.toString());
      }

      if (intervalMinutes != null) {
        pairs.putPair(KEY_INTERVAL_MINUTES, intervalMinutes.toString());
      }
    }

    if (CollectionUtil.isNonEmpty(extensionOids)) {
      StringBuilder extensionsSb = new StringBuilder(200);
      for (String oid : extensionOids) {
        extensionsSb.append(oid).append(",");
      }
      extensionsSb.deleteCharAt(extensionsSb.length() - 1);
      pairs.putPair(KEY_EYTENSIONS, extensionsSb.toString());
    }

    return pairs.getEncoded();
  } // method getConf

  @Override
  public String toString() {
    return toString(false);
  }

  public String toString(boolean verbose) {
    StringBuilder sb = new StringBuilder(xipkiCertsetIncluded ? "included" : "not included");

    if (xipkiCertsetIncluded) {
      sb.append("\t\tinclude cert: ").append(xipkiCertsetCertIncluded);
    }
    String xipkiCertSetStr = sb.toString();

    sb = new StringBuilder("generate CRL ");
    if (intervalDayTime != null) {
      sb.append("at ").append(intervalDayTime);
    } else {
      sb.append("every ").append(intervalMinutes).append(" minutes");
    }
    String intervalStr = sb.toString();

    return StringUtil.concatObjects("  update mode: ", updateMode,
        "\n  include expired certificates: ", includeExpiredCerts,
        "\n  full CRL intervals: ", fullCrlIntervals,
        "\n  delta CRL intervals: ", deltaCrlIntervals,
        "\n  overlap: ", overlapMinutes, " minutes",
        "\n  use extended nextUpdate: ", extendedNextUpdate,
        "\n  only user certificates: ", onlyContainsUserCerts,
        "\n  only CA certificates: ", onlyContainsCaCerts,
        "\n  exclude reason: ", excludeReason,
        "\n  invalidity date mode: ", invalidityDateMode,
        "\n  interval: ", intervalStr,
        "\n  XiPKI CertSet: ", xipkiCertSetStr,
        (verbose ? "\n  encoded: " : ""), (verbose ? getConf() : ""));
  }

  public UpdateMode getUpdateMode() {
    return updateMode;
  }

  public boolean isXipkiCertsetIncluded() {
    return xipkiCertsetIncluded;
  }

  public boolean isXipkiCertsetCertIncluded() {
    return xipkiCertsetCertIncluded;
  }

  public boolean isIncludeExpiredCerts() {
    return includeExpiredCerts;
  }

  public int getFullCrlIntervals() {
    return fullCrlIntervals;
  }

  public int getDeltaCrlIntervals() {
    return deltaCrlIntervals;
  }

  public int getOverlapMinutes() {
    return overlapMinutes;
  }

  public Integer getIntervalMinutes() {
    return intervalMinutes;
  }

  public HourMinute getIntervalDayTime() {
    return intervalDayTime;
  }

  public Set<String> getExtensionOids() {
    return extensionOids;
  }

  public boolean isExtendedNextUpdate() {
    return extendedNextUpdate;
  }

  public boolean isOnlyContainsUserCerts() {
    return onlyContainsUserCerts;
  }

  public boolean isOnlyContainsCaCerts() {
    return onlyContainsCaCerts;
  }

  public boolean isExcludeReason() {
    return excludeReason;
  }

  public TripleState getInvalidityDateMode() {
    return invalidityDateMode;
  }

  public final void validate() throws InvalidConfException {
    if (onlyContainsCaCerts && onlyContainsUserCerts) {
      throw new InvalidConfException(
          "onlyContainsCACerts and onlyContainsUserCerts can not be both true");
    }

    if (updateMode == UpdateMode.ONDEMAND) {
      return;
    }

    if (fullCrlIntervals < deltaCrlIntervals) {
      throw new InvalidConfException(
          "fullCRLIntervals must not be less than deltaCRLIntervals "
          + fullCrlIntervals + " < " + deltaCrlIntervals);
    }

    if (fullCrlIntervals < 1) {
      throw new InvalidConfException(
          "fullCRLIntervals must not be less than 1: " + fullCrlIntervals);
    }

    if (deltaCrlIntervals < 0) {
      throw new InvalidConfException(
          "deltaCRLIntervals must not be less than 0: " + deltaCrlIntervals);
    }
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof CrlControl)) {
      return false;
    }

    CrlControl obj2 = (CrlControl) obj;
    if (deltaCrlIntervals != obj2.deltaCrlIntervals
        || xipkiCertsetIncluded != obj2.xipkiCertsetIncluded
        || xipkiCertsetCertIncluded != obj2.xipkiCertsetCertIncluded
        || extendedNextUpdate != obj2.extendedNextUpdate
        || fullCrlIntervals != obj2.fullCrlIntervals
        || includeExpiredCerts != obj2.includeExpiredCerts
        || onlyContainsCaCerts != obj2.onlyContainsCaCerts
        || onlyContainsUserCerts != obj2.onlyContainsUserCerts) {
      return false;
    }

    if (extensionOids == null) {
      if (obj2.extensionOids != null) {
        return false;
      }
    } else if (!extensionOids.equals(obj2.extensionOids)) {
      return false;
    }

    if (intervalMinutes == null) {
      if (obj2.intervalMinutes != null) {
        return false;
      }
    } else if (!intervalMinutes.equals(obj2.intervalMinutes)) {
      return false;
    }

    if (intervalDayTime == null) {
      if (obj2.intervalDayTime != null) {
        return false;
      }
    } else if (!intervalDayTime.equals(obj2.intervalDayTime)) {
      return false;
    }

    if (updateMode == null) {
      if (obj2.updateMode != null) {
        return false;
      }
    } else if (!updateMode.equals(obj2.updateMode)) {
      return false;
    }

    return true;
  } // method equals

  private static int getInteger(ConfPairs props, String propKey, int dfltValue)
      throws InvalidConfException {
    String str = props.value(propKey);
    if (str != null) {
      try {
        return Integer.parseInt(str.trim());
      } catch (NumberFormatException ex) {
        throw new InvalidConfException(propKey + " does not have numeric value: " + str);
      }
    }
    return dfltValue;
  }

  private static boolean getBoolean(ConfPairs props, String propKey, boolean dfltValue)
      throws InvalidConfException {
    String str = props.value(propKey);
    if (str != null) {
      str = str.trim();
      if ("true".equalsIgnoreCase(str)) {
        return Boolean.TRUE;
      } else if ("false".equalsIgnoreCase(str)) {
        return Boolean.FALSE;
      } else {
        throw new InvalidConfException(propKey + " does not have boolean value: " + str);
      }
    }
    return dfltValue;
  }

}
