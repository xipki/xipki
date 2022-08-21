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

import org.xipki.util.*;
import org.xipki.util.exception.InvalidConfException;

import java.util.List;

/**
 * CRL control.
 *<pre>
 * Example configuration
 *
 * # The following settings are only for updateMode 'interval'
 *
 * # Intervals between two full CRLs. Default is 1.
 * # Should be greater than 0
 * fullcrl.intervals=&lt;integer&gt;
 *
 * # Elapsed intervals before a deltaCRL is generated since the last CRL or deltaCRL.
 * # Should be 0 or a positive integer less than fullcrl.intervals. Default is 0.
 * # 0 indicates that no deltaCRL will be generated
 * deltacrl.intervals=&lt;integer&gt;
 *
 * # Overlap time, unit is m (minutes), h (hour), d (day), w (week), y (year).
 * overlap=&lt;integer&gt;&lt;unit&gt;
 *
 * # Interval period in hours, valid values are 1, 2, 3, 4, 6, 8, 12 and 24.
 * #
 * # Default is 24.
 * interval.hours=&lt;integer&gt;
 *
 * # UTC time at which CRL is generated, Default is 01:00.
 * # If day.intervals is greater than 1, this specifies only one of the generation times.
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
 * # Default is optional
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

  public static final String KEY_FULLCRL_INTERVALS = "fullcrl.intervals";

  public static final String KEY_DELTACRL_INTERVALS = "deltacrl.intervals";

  /**
   * Overlap in minutes.
   * @deprecated use {@link #KEY_OVERLAP} instead.
   */
  public static final String KEY_OVERLAP_MINUTES = "overlap.minutes";

  /**
   * Overlap in days.
   * @deprecated use {@link #KEY_OVERLAP} instead.
   */
  public static final String KEY_OVERLAP_DAYS = "overlap.days";

  /**
   * Overlap.
   */
  public static final String KEY_OVERLAP = "overlap";

  public static final String KEY_INTERVAL_HOURS = "interval.hours";

  public static final String KEY_INTERVAL_TIME = "interval.time";

  public static final String KEY_FULLCRL_EXTENDED_NEXTUPDATE = "fullcrl.extended.nextupdate";

  public static final String KEY_EXCLUDE_REASON = "exclude.reason";

  public static final String KEY_INCLUDE_EXPIREDCERTS = "include.expiredcerts";

  public static final String KEY_INVALIDITY_DATE = "invalidity.date";

  private final int fullCrlIntervals;

  private final int deltaCrlIntervals;

  private final int intervalHours;

  private final long intervalMillis;

  private final Validity overlap;

  private final boolean extendedNextUpdate;

  private final HourMinute intervalDayTime;

  private final boolean excludeReason;

  private final boolean includeExpiredCerts;

  private TripleState invalidityDateMode = TripleState.optional;

  public CrlControl(String conf)
      throws InvalidConfException {
    this(toConfPairs(conf));
  }

  private static ConfPairs toConfPairs(String conf)
      throws InvalidConfException {
    try {
      return new ConfPairs(conf);
    } catch (RuntimeException ex) {
      throw new InvalidConfException(ex.getClass().getName() + ": " + ex.getMessage(), ex);
    }
  }

  public CrlControl(ConfPairs props)
      throws InvalidConfException {
    Args.notNull(props, "props");

    String str = props.value(KEY_INVALIDITY_DATE);
    if (str != null) {
      this.invalidityDateMode = TripleState.valueOf(str);
    }

    this.excludeReason = getBoolean(props, KEY_EXCLUDE_REASON, false);
    this.includeExpiredCerts = getBoolean(props, KEY_INCLUDE_EXPIREDCERTS, false);

    // Maximal interval allowed by CA/Browser Forum's Baseline Requirements
    this.fullCrlIntervals = getInteger(props, KEY_FULLCRL_INTERVALS, 7);
    this.deltaCrlIntervals = getInteger(props, KEY_DELTACRL_INTERVALS, 0);
    this.extendedNextUpdate = getBoolean(props, KEY_FULLCRL_EXTENDED_NEXTUPDATE, false);

    Validity ov;
    if (props.value(KEY_OVERLAP_DAYS) != null) {
      ov = new Validity(getInteger(props, KEY_OVERLAP_DAYS, 1), Validity.Unit.DAY);
    } else if (props.value(KEY_OVERLAP_MINUTES) != null) {
      ov = new Validity(getInteger(props, KEY_OVERLAP_MINUTES, 24 * 60), Validity.Unit.MINUTE);
    } else if (props.value(KEY_OVERLAP) != null) {
      ov = Validity.getInstance(props.value(KEY_OVERLAP));
    } else {
      ov = new Validity(1, Validity.Unit.DAY);
    }

    if (ov.getValidity() < 1) {
      // Maximal overlap allowed by CA/Browser Forum's Baseline Requirements
      this.overlap = new Validity(3, Validity.Unit.DAY);
    } else {
      this.overlap = ov;
    }

    int hours = getInteger(props, KEY_INTERVAL_HOURS, 24);
    if (!(hours >= 1 && hours <= 24 && (24 - 24 / hours * hours == 0))) {
      throw new InvalidConfException(KEY_INTERVAL_HOURS + " " + hours + " not in [1,2,3,4,6,8,12,24]");
    }
    this.intervalHours = hours;
    this.intervalMillis = hours * 60L * 60 * 1000;

    str = props.value(KEY_INTERVAL_TIME);

    HourMinute hm;
    if (str == null) {
      hm = new HourMinute(1, 0);
    } else {
      List<String> tokens = StringUtil.split(str.trim(), ":");
      if (tokens.size() != 2) {
        throw new InvalidConfException("invalid " + KEY_INTERVAL_TIME + ": '" + str + "'");
      }

      try {
        int hour = Integer.parseInt(tokens.get(0));
        int minute = Integer.parseInt(tokens.get(1));
        hm = new HourMinute(hour, minute);
      } catch (IllegalArgumentException ex) {
        throw new InvalidConfException("invalid " + KEY_INTERVAL_TIME + ": '" + str + "'");
      }
    }

    int i = 0;
    while (true) {
      if (hm.getHour() - (i + 1) * intervalHours < 0) {
        break;
      }

      i++;
    }

    this.intervalDayTime = i == 0 ? hm : new HourMinute(hm.getHour() - i * intervalHours, hm.getMinute());

    validate();
  } // constructor

  public String getConf() {
    return getConfPairs().getEncoded();
  }

  public ConfPairs getConfPairs() {
    ConfPairs pairs = new ConfPairs();
    pairs.putPair(KEY_DELTACRL_INTERVALS, Integer.toString(deltaCrlIntervals));
    pairs.putPair(KEY_EXCLUDE_REASON, Boolean.toString(excludeReason));
    pairs.putPair(KEY_INCLUDE_EXPIREDCERTS, Boolean.toString(includeExpiredCerts));
    pairs.putPair(KEY_FULLCRL_EXTENDED_NEXTUPDATE, Boolean.toString(extendedNextUpdate));
    pairs.putPair(KEY_FULLCRL_INTERVALS, Integer.toString(fullCrlIntervals));
    pairs.putPair(KEY_INTERVAL_HOURS, Integer.toString(intervalHours));
    pairs.putPair(KEY_INTERVAL_TIME, intervalDayTime.toString());
    pairs.putPair(KEY_INVALIDITY_DATE, invalidityDateMode.name());
    pairs.putPair(KEY_OVERLAP, overlap.toString());
    return pairs;
  } // method getConf

  @Override
  public String toString() {
    return toString(false);
  }

  public String toString(boolean verbose) {
    return StringUtil.concatObjects(
        "  interval unit: ", intervalHours, " hours",
        "\n  full CRL intervals: ", fullCrlIntervals,
        "\n  delta CRL intervals: ", deltaCrlIntervals,
        "\n  overlap: ", overlap,
        "\n  use extended nextUpdate: ", extendedNextUpdate,
        "\n  exclude reason: ", excludeReason,
        "\n  include expired certs: ", includeExpiredCerts,
        "\n  invalidity date mode: ", invalidityDateMode,
        "\n  intervalDayTime: ", "generate CRL at " + intervalDayTime, " UTC",
        (verbose ? "\n  encoded: " : ""), (verbose ? getConf() : ""));
  } // method toString(boolean)

  public int getFullCrlIntervals() {
    return fullCrlIntervals;
  }

  public int getDeltaCrlIntervals() {
    return deltaCrlIntervals;
  }

  public Validity getOverlap() {
    return overlap;
  }

  public HourMinute getIntervalDayTime() {
    return intervalDayTime;
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

  public int getIntervalHours() {
    return intervalHours;
  }

  public long getIntervalMillis() {
    return intervalMillis;
  }

  public final void validate()
      throws InvalidConfException {
    if (fullCrlIntervals < deltaCrlIntervals) {
      throw new InvalidConfException(
          "fullCRLIntervals may not be less than deltaCRLIntervals " + fullCrlIntervals + " < " + deltaCrlIntervals);
    }

    if (fullCrlIntervals < 1) {
      throw new InvalidConfException("fullCRLIntervals may not be less than 1: " + fullCrlIntervals);
    }

    if (deltaCrlIntervals < 0) {
      throw new InvalidConfException("deltaCRLIntervals may not be less than 0: " + deltaCrlIntervals);
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
    return deltaCrlIntervals == obj2.deltaCrlIntervals
            && excludeReason == obj2.excludeReason
            && extendedNextUpdate == obj2.extendedNextUpdate
            && fullCrlIntervals == obj2.fullCrlIntervals
            && includeExpiredCerts == obj2.includeExpiredCerts
            && intervalDayTime.equals(obj2.intervalDayTime)
            && intervalHours == obj2.intervalHours
            && invalidityDateMode.equals(obj2.invalidityDateMode)
            && overlap.equals(obj2.overlap);
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
