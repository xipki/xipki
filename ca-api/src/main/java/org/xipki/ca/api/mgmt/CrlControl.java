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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.*;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * CRL control.
 *<pre>
 * Example configuration
 *
 * # List of OIDs of extensions to be embedded in CRL,
 * # Unspecified or empty extensions indicates that the CA decides.
 * extensions=&lt;comma delimited OIDs of extensions&gt;
 *
 * # The following settings are only for updateMode 'interval'
 *
 * # Days between two full CRLs. Default is 1.
 * # Should be greater than 0
 * fullcrl.intervals=&lt;integer&gt;
 *
 * # Elapsed days before a deltaCRL is generated since the last CRL or deltaCRL.
 * # Should be 0 or a positive integer less than fullcrl.intervals. Default is 0.
 * # 0 indicates that no deltaCRL will be generated
 * deltacrl.intervals=&lt;integer&gt;
 *
 * # Overlap days. At least 1 day
 * overlap.days=&lt;days of overlap&gt;
 *
 * # UTC time of generation of CRL, one interval covers 1 day. Default is 01:00
 * interval.time=&lt;update time (hh:mm of UTC time)&gt;
 *
 * # If set to true, the nextUpdate of a fullCRL is set to the update time of the next fullCRL.
 * # otherwise set to that of the next CRL (fullCRL or deltaCRL)
 * # Default is false
 * fullcrl.extended.nextupdate=&lt;'true'|'false'&gt;
 *
 * # Whether Revocation reason is contained in CRL
 * # Default is false
 * exclude.reason=&lt;'true'|'false'&gt;
 *
 * # How the CRL entry extension invalidityDate is considered in CRL
 * # Default is false
 * invalidity.date=&lt;'required'|'optional'|'forbidden'&gt;
 *
 * # Whether to include the expired certificates
 * # Default is false
 * include.expiredcerts=&lt;'true'|'false'&gt;
 *
 * </pre>
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CrlControl {

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

  public static final String KEY_EYTENSIONS = "extensions";

  public static final String KEY_FULLCRL_INTERVALS = "fullcrl.intervals";

  public static final String KEY_DELTACRL_INTERVALS = "deltacrl.intervals";

  /**
   * Overlap in minutes.
   * @deprecated use {@link #KEY_OVERLAP_DAYS} instead.
   */
  public static final String KEY_OVERLAP_MINUTES = "overlap.minutes";

  public static final String KEY_OVERLAP_DAYS = "overlap.days";

  public static final String KEY_INTERVAL_TIME = "interval.time";

  public static final String KEY_FULLCRL_EXTENDED_NEXTUPDATE = "fullcrl.extended.nextupdate";

  public static final String KEY_EXCLUDE_REASON = "exclude.reason";

  public static final String KEY_INCLUDE_EXPIREDCERTS = "include.expiredcerts";

  public static final String KEY_INVALIDITY_DATE = "invalidity.date";

  private final int fullCrlIntervals;

  private final int deltaCrlIntervals;

  private int overlapDays = 3;

  private final boolean extendedNextUpdate;

  private final HourMinute intervalDayTime;

  private final boolean excludeReason;

  private final boolean includeExpiredCerts;

  private TripleState invalidityDateMode = TripleState.optional;

  private final Set<String> extensionOids;

  public CrlControl(String conf)
      throws InvalidConfException {
    ConfPairs props;
    try {
      props = new ConfPairs(conf);
    } catch (RuntimeException ex) {
      throw new InvalidConfException(ex.getClass().getName() + ": " + ex.getMessage(), ex);
    }

    String str = props.value(KEY_INVALIDITY_DATE);
    if (str != null) {
      this.invalidityDateMode = TripleState.valueOf(str);
    }

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

    this.excludeReason = getBoolean(props, KEY_EXCLUDE_REASON, false);
    this.includeExpiredCerts = getBoolean(props, KEY_INCLUDE_EXPIREDCERTS, false);

    // Maximal interval allowed by CA/Browser Forum's Baseline Requirements
    this.fullCrlIntervals = getInteger(props, KEY_FULLCRL_INTERVALS, 7);
    this.deltaCrlIntervals = getInteger(props, KEY_DELTACRL_INTERVALS, 0);
    this.extendedNextUpdate = getBoolean(props, KEY_FULLCRL_EXTENDED_NEXTUPDATE, false);

    if (props.value(KEY_OVERLAP_DAYS) != null) {
      this.overlapDays = getInteger(props, KEY_OVERLAP_DAYS, 1);
    } else if (props.value(KEY_OVERLAP_MINUTES) != null) {
      int minutes = getInteger(props, KEY_OVERLAP_MINUTES, 1);
      // convert minutes to days.
      this.overlapDays = (minutes + 24 * 60 - 1) / (24 * 60);
    }

    if (this.overlapDays < 1) {
      // Maximal overlap allowed by CA/Browser Forum's Baseline Requirements
      this.overlapDays = 3;
    }

    str = props.value(KEY_INTERVAL_TIME);
    if (str == null) {
      this.intervalDayTime = new HourMinute(1, 0);
    } else {
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
    }

    validate();
  } // constructor

  public String getConf() {
    ConfPairs pairs = new ConfPairs();
    pairs.putPair(KEY_DELTACRL_INTERVALS, Integer.toString(deltaCrlIntervals));
    pairs.putPair(KEY_EXCLUDE_REASON, Boolean.toString(excludeReason));
    pairs.putPair(KEY_INCLUDE_EXPIREDCERTS, Boolean.toString(includeExpiredCerts));
    pairs.putPair(KEY_FULLCRL_EXTENDED_NEXTUPDATE, Boolean.toString(extendedNextUpdate));
    pairs.putPair(KEY_FULLCRL_INTERVALS, Integer.toString(fullCrlIntervals));
    pairs.putPair(KEY_INTERVAL_TIME, intervalDayTime.toString());
    pairs.putPair(KEY_INVALIDITY_DATE, invalidityDateMode.name());
    pairs.putPair(KEY_OVERLAP_DAYS, Integer.toString(overlapDays));

    if (CollectionUtil.isNotEmpty(extensionOids)) {
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
    return StringUtil.concatObjects(
        "  full CRL intervals: ", fullCrlIntervals,
        "\n  delta CRL intervals: ", deltaCrlIntervals,
        "\n  overlap: ", overlapDays, " days",
        "\n  use extended nextUpdate: ", extendedNextUpdate,
        "\n  exclude reason: ", excludeReason,
        "\n  include expired certs: ", includeExpiredCerts,
        "\n  invalidity date mode: ", invalidityDateMode,
        "\n  intervalDayTime: ", "generate CRL at " + intervalDayTime,
        (verbose ? "\n  encoded: " : ""), (verbose ? getConf() : ""));
  } // method toString(boolean)

  public int getFullCrlIntervals() {
    return fullCrlIntervals;
  }

  public int getDeltaCrlIntervals() {
    return deltaCrlIntervals;
  }

  public int getOverlapDays() {
    return overlapDays;
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

  public boolean isExcludeReason() {
    return excludeReason;
  }

  public boolean isIncludeExpiredcerts() {
    return includeExpiredCerts;
  }

  public TripleState getInvalidityDateMode() {
    return invalidityDateMode;
  }

  public final void validate()
      throws InvalidConfException {
    if (fullCrlIntervals < deltaCrlIntervals) {
      throw new InvalidConfException(
          "fullCRLIntervals may not be less than deltaCRLIntervals "
          + fullCrlIntervals + " < " + deltaCrlIntervals);
    }

    if (fullCrlIntervals < 1) {
      throw new InvalidConfException(
          "fullCRLIntervals may not be less than 1: " + fullCrlIntervals);
    }

    if (deltaCrlIntervals < 0) {
      throw new InvalidConfException(
          "deltaCRLIntervals may not be less than 0: " + deltaCrlIntervals);
    }
  } // method validate

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
        || extendedNextUpdate != obj2.extendedNextUpdate
        || fullCrlIntervals != obj2.fullCrlIntervals
        || includeExpiredCerts != obj2.includeExpiredCerts) {
      return false;
    }

    if (extensionOids == null) {
      if (obj2.extensionOids != null) {
        return false;
      }
    } else if (!extensionOids.equals(obj2.extensionOids)) {
      return false;
    }

    return intervalDayTime.equals(obj2.intervalDayTime);
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
  } // method getInteger

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
  } // method getBoolean

}
