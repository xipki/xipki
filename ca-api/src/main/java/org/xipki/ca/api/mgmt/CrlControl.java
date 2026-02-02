// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.TripleState;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.type.HourMinute;
import org.xipki.util.extra.type.Validity;
import org.xipki.util.misc.StringUtil;

import java.util.List;

/**
 * CRL control.
 *<pre>
 * Example configuration
 *
 * # The following settings are only for updateMode 'interval'
 *
 * # Intervals between two full CRLs. Default is 1.
 * # Valid values depends on interval.hours:
 * # -  1 hour:  any positive number
 * # -  2 hours: 1, 2, 3, 4, 6, 12, 24, 36, ...(+12 = 24/2)
 * # -  3 hours: 1, 2, 4,        8, 16, 24, ...(+8  = 24/3)
 * # -  4 hours: 1, 2, 3,        6, 12, 18, ...(+6  = 24/4)
 * # -  6 hours: 1, 2,           4,  8, 12, ...(+4  = 24/6)
 * # -  8 hours: 1,              3,  6,  9, ...(+3  = 24/8)
 * # - 12 hours: 1,              2,  4,  6, ...(+2  = 24/12)
 * # - 24 hours: any positive number
 *
 * fullcrl.intervals=&lt;integer&gt;
 *
 * # Elapsed intervals before a deltaCRL is generated since the last CRL or
 * # deltaCRL.
 * # Should be 0 or a positive integer less than fullcrl.intervals. Default
 * # is 0.
 * # 0 indicates that no deltaCRL will be generated
 * #
 * # Valid values depends on interval.hours:
 * # -  1 hour:  any positive number
 * # -  2 hours: 1, 2, 3, 4, 6, 12, 24, 36, ...(+12 = 24/2)
 * # -  3 hours: 1, 2, 4,        8, 16, 24, ...(+8  = 24/3)
 * # -  4 hours: 1, 2, 3,        6, 12, 18, ...(+6  = 24/4)
 * # -  6 hours: 1, 2,           4,  8, 12, ...(+4  = 24/6)
 * # -  8 hours: 1,              3,  6,  9, ...(+3  = 24/8)
 * # - 12 hours: 1,              2,  4,  6, ...(+2  = 24/12)
 * # - 24 hours: any positive number
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
 * interval.time=&lt;update time (hh:mm of UTC time)&gt;
 *
 * # If set to true, the nextUpdate of a fullCRL is set to the update time of
 * # the next fullCRL.
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
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */

public class CrlControl implements JsonEncodable {

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

  public static final String KEY_FULLCRL_EXTENDED_NEXTUPDATE =
      "fullcrl.extended.nextupdate";

  public static final String KEY_EXCLUDE_REASON = "exclude.reason";

  public static final String KEY_INCLUDE_EXPIREDCERTS = "include.expiredcerts";

  public static final String KEY_INVALIDITY_DATE = "invalidity.date";

  private final int fullCrlIntervals;

  private final int deltaCrlIntervals;

  private final int intervalHours;

  private final Validity overlap;

  private final boolean extendedNextUpdate;

  private final HourMinute intervalDayTime;

  private final boolean excludeReason;

  private final boolean includeExpiredCerts;

  private TripleState invalidityDateMode = TripleState.optional;

  public CrlControl(String conf) throws InvalidConfException {
    this(toConfPairs(conf));
  }

  private static ConfPairs toConfPairs(String conf)
      throws InvalidConfException {
    try {
      return new ConfPairs(conf);
    } catch (RuntimeException ex) {
      throw new InvalidConfException(
          ex.getClass().getName() + ": " + ex.getMessage(), ex);
    }
  }

  public CrlControl(ConfPairs props) throws InvalidConfException {
    Args.notNull(props, "props");

    String str = props.value(KEY_INVALIDITY_DATE);
    if (str != null) {
      this.invalidityDateMode = TripleState.valueOf(str);
    }

    this.excludeReason = getBoolean(props, KEY_EXCLUDE_REASON, false);
    this.includeExpiredCerts =
        getBoolean(props, KEY_INCLUDE_EXPIREDCERTS, false);

    int h = getInteger(props, KEY_INTERVAL_HOURS, 24);
    if (h != 1 && h != 2 && h != 3 && h != 4 && h != 6 && h != 8
        && h != 12 && h != 24) {
      throw new InvalidConfException(KEY_INTERVAL_HOURS + " " + h +
          " not in [1,2,3,4,6,8,12,24]");
    }

    this.intervalHours = h;
    // Maximal interval allowed by CA/Browser Forum's Baseline Requirements
    this.fullCrlIntervals   = getInteger(props,
        KEY_FULLCRL_INTERVALS, 7 * 24 / h);
    this.deltaCrlIntervals  = getInteger(props,
        KEY_DELTACRL_INTERVALS, 0);
    this.extendedNextUpdate = getBoolean(props,
        KEY_FULLCRL_EXTENDED_NEXTUPDATE, false);

    Validity ov;
    if (props.value(KEY_OVERLAP_DAYS) != null) {
      ov = new Validity(getInteger(props, KEY_OVERLAP_DAYS, 1),
              Validity.Unit.DAY);
    } else if (props.value(KEY_OVERLAP_MINUTES) != null) {
      ov = new Validity(getInteger(props, KEY_OVERLAP_MINUTES, 24 * 60),
              Validity.Unit.MINUTE);
    } else if (props.value(KEY_OVERLAP) != null) {
      ov = Validity.getInstance(props.value(KEY_OVERLAP));
    } else {
      ov = new Validity(1, Validity.Unit.DAY);
    }

    if (ov.validity() < 1) {
      // Maximal overlap allowed by CA/Browser Forum's Baseline Requirements
      this.overlap = new Validity(3, Validity.Unit.DAY);
    } else {
      this.overlap = ov;
    }

    str = props.value(KEY_INTERVAL_TIME);

    HourMinute hm;
    if (str == null) {
      hm = new HourMinute(1, 0);
    } else {
      List<String> tokens = StringUtil.split(str.trim(), ":");
      if (tokens.size() != 2) {
        throw new InvalidConfException(
            "invalid " + KEY_INTERVAL_TIME + ": '" + str + "'");
      }

      try {
        int hour = Integer.parseInt(tokens.get(0));
        int minute = Integer.parseInt(tokens.get(1));
        hm = new HourMinute(hour, minute);
      } catch (IllegalArgumentException ex) {
        throw new InvalidConfException(
            "invalid " + KEY_INTERVAL_TIME + ": '" + str + "'");
      }
    }

    int i = 0;
    while (true) {
      if (hm.hour() - (i + 1) * intervalHours < 0) {
        break;
      }

      i++;
    }

    this.intervalDayTime = i == 0 ? hm
        : new HourMinute(hm.hour() - i * intervalHours, hm.minute());

    validate();
  } // constructor

  public String getConf() {
    return getConfPairs().getEncoded();
  }

  public ConfPairs getConfPairs() {
    return new ConfPairs()
        .putPair(KEY_DELTACRL_INTERVALS,   Integer.toString(deltaCrlIntervals))
        .putPair(KEY_EXCLUDE_REASON,       Boolean.toString(excludeReason))
        .putPair(KEY_INCLUDE_EXPIREDCERTS,
            Boolean.toString(includeExpiredCerts))
        .putPair(KEY_FULLCRL_EXTENDED_NEXTUPDATE,
            Boolean.toString(extendedNextUpdate))
        .putPair(KEY_FULLCRL_INTERVALS,    Integer.toString(fullCrlIntervals))
        .putPair(KEY_INTERVAL_HOURS,       Integer.toString(intervalHours))
        .putPair(KEY_INTERVAL_TIME,        intervalDayTime.toString())
        .putPair(KEY_INVALIDITY_DATE,      invalidityDateMode.name())
        .putPair(KEY_OVERLAP,              overlap.toString());
  } // method getConf

  @Override
  public String toString() {
    return toString(false);
  }

  public String toString(boolean verbose) {
    return StringUtil.concatObjects(
        "  interval unit:           ", intervalHours, " hours",
        "\n  full CRL intervals:      ", fullCrlIntervals,
        "\n  delta CRL intervals:     ", deltaCrlIntervals,
        "\n  overlap:                 ", overlap,
        "\n  use extended nextUpdate: ", extendedNextUpdate,
        "\n  exclude reason:          ", excludeReason,
        "\n  include expired certs:   ", includeExpiredCerts,
        "\n  invalidity date mode:    ", invalidityDateMode,
        "\n  intervalDayTime:         ", "generate CRL at " + intervalDayTime,
        " UTC", (verbose ? "\n  encoded:                 " : ""),
        (verbose ? getConf() : ""));
  } // method toString(boolean)

  public int fullCrlIntervals() {
    return fullCrlIntervals;
  }

  public int deltaCrlIntervals() {
    return deltaCrlIntervals;
  }

  public Validity overlap() {
    return overlap;
  }

  public HourMinute intervalDayTime() {
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

  public TripleState invalidityDateMode() {
    return invalidityDateMode;
  }

  public int intervalHours() {
    return intervalHours;
  }

  public final void validate() throws InvalidConfException {
    int h = intervalHours;
    if (!(h == 1 || h == 2 || h == 3 || h == 4 || h == 6
        || h == 8 || h == 12 || h == 24)) {
      throw new InvalidConfException(intervalHours + " " + h +
          " not in [1,2,3,4,6,8,12,24]");
    }

    if (deltaCrlIntervals < 0) {
      throw new InvalidConfException(
          "deltaCRLIntervals may not be less than 0: " + deltaCrlIntervals);
    } else if (deltaCrlIntervals > 0 && deltaCrlIntervals >= fullCrlIntervals) {
      throw new InvalidConfException(
          "deltaCrlIntervals shall not be greater than or equal to " +
          "fullCrlIntervals: " + deltaCrlIntervals + " >= " + fullCrlIntervals);
    }

    int prod = fullCrlIntervals * intervalHours;
    if (!(fullCrlIntervals > 0 && (prod % 24 == 0 || 24 % prod == 0))) {
      throw new InvalidConfException(
          "invalid fullCRLIntervals: " + fullCrlIntervals);
    }

    if (deltaCrlIntervals > 0) {
      prod = deltaCrlIntervals * intervalHours;
      if (!(prod % 24 == 0 || 24 % prod == 0)) {
        throw new InvalidConfException(
            "invalid deltaCRLIntervals: " + deltaCrlIntervals);
      }
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
        throw new InvalidConfException(
            propKey + " does not have numeric value: " + str);
      }
    }
    return dfltValue;
  } // method getInteger

  private static boolean getBoolean(
      ConfPairs props, String propKey, boolean dfltValue)
      throws InvalidConfException {
    String str = props.value(propKey);
    if (str != null) {
      str = str.trim();
      if ("true".equalsIgnoreCase(str)) {
        return Boolean.TRUE;
      } else if ("false".equalsIgnoreCase(str)) {
        return Boolean.FALSE;
      } else {
        throw new InvalidConfException(propKey +
            " does not have boolean value: " + str);
      }
    }
    return dfltValue;
  } // method getBoolean

  @Override
  public JsonMap toCodec() {
    return new JsonMap(getConfPairs().asMap());
  }

}
