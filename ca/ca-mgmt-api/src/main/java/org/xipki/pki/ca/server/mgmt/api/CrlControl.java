/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.server.mgmt.api;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.InvalidConfException;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;

/**
 *<pre>
 * Example configuration
 * updateMode=<'interval'|'onDemand'>
 *
 * # For all updateMode
 *
 * # Whether expired certificates are considered. Default is false
 * expiredCerts.included=&lt;'true'|'false'>
 *
 * # Whether XiPKI-customized extension xipki-CrlCertSet is included. Default is false
 * xipki.certset=&lt;'true'|'false'>
 *
 * # Whether the extension xipki-CrlCertSet contains the raw certificates. Default is true
 * xipki.certset.certs=&lt;'true'|'false'>
 *
 * # Whether the extension xipki-CrlCertSet contains the profile name of the certificate.
 * # Default is true
 * xipki.certset.profilename=&lt;'true'|'false'>
 *
 * # List of OIDs of extensions to be embedded in CRL,
 * # Unspecified or empty extensions indicates that the CA decides.
 * extensions=&lt;comma delimited OIDs of extensions>
 *
 * # The following settings are only for updateMode 'interval'
 *
 * # Number of intervals to generate a full CRL. Default is 1
 * # Should be greater than 0
 * fullCRL.intervals=&lt;integer>
 *
 * # should be 0 or not greater than baseCRL.intervals. Default is 0.
 * # 0 indicates that no deltaCRL will be generated
 * deltaCRL.intervals=&lt;integer>
 *
 * overlap.minutes=&lt;minutes of overlap>
 *
 * # should be less than fullCRL.intervals.
 * # If activated, a deltaCRL will be generated only between two full CRLs
 * deltaCRL.intervals=&lt;integer>
 *
 * # Exactly one of interval.minutes and interval.days should be specified
 * # Number of minutes of one interval. At least 60 minutes
 * interval.minutes=&lt;minutes of one interval>
 *
 * # UTC time of generation of CRL, one interval covers 1 day.
 * interval.time=&lt;updatet time (hh:mm of UTC time)>
 *
 * # Whether the nextUpdate of a fullCRL is the update time of the fullCRL
 * # Default is false
 * fullCRL.extendedNextUpdate=&lt;'true'|'false'>
 *
 * # Whether only user certificates are considered in CRL
 * # Default is false
 * onlyContainsUserCerts=&lt;'true'|'false'>
 *
 * # Whether only CA certificates are considered in CRL
 * # Default if false
 * onlyContainsCACerts=&lt;'true'|'false'>
 *
 * # Whether Revocation reason is contained in CRL
 * # Default is false
 * excludeReason=&lt;'true'|'false'>
 *
 * # How the CRL entry extension invalidityDate is considered in CRL
 * # Default is false
 * invalidityDate=&lt;'required'|'optional'|'forbidden'>
 *
 * </pre>
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CrlControl implements Serializable {

    public enum UpdateMode implements Serializable {

        interval,
        onDemand;

        public static UpdateMode getUpdateMode(
                final String mode) {
            ParamUtil.requireNonNull("mode", mode);
            for (UpdateMode v : values()) {
                if (v.name().equalsIgnoreCase(mode)) {
                    return v;
                }
            }

            return null;
        }

    } // enum UpdateMode

    public static class HourMinute implements Serializable {

        private static final long serialVersionUID = 1L;

        private final int hour;

        private final int minute;

        public HourMinute(
                final int hour,
                final int minute) {
            this.hour = ParamUtil.requireRange("hour", hour, 0, 23);
            this.minute = ParamUtil.requireRange("minute", minute, 0, 59);
        }

        public int getHour() {
            return hour;
        }

        public int getMinute() {
            return minute;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder(100);
            if (hour < 10) {
                sb.append("0");
            }
            sb.append(hour);
            sb.append(":");
            if (minute < 10) {
                sb.append("0");
            }
            sb.append(minute);
            return sb.toString();
        }

        @Override
        public int hashCode() {
            return toString().hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof HourMinute)) {
                return false;
            }

            HourMinute hm = (HourMinute) obj;
            return hour == hm.hour && minute == hm.minute;
        }

    } // class HourMinute

    public static final String KEY_UPDATE_MODE = "updateMode";

    public static final String KEY_EYTENSIONS = "extensions";

    public static final String KEY_EXPIRED_CERTS_INCLUDED = "expiredCerts.included";

    public static final String KEY_XIPKI_CERTSET = "xipki.certset";

    public static final String KEY_XIPKI_CERTSET_CERTS = "xipki.certset.certs";

    public static final String KEY_XIPKI_CERTSET_PROFILENAME = "xipki.certset.profilename";

    public static final String KEY_FULLCRL_INTERVALS = "fullCRL.intervals";

    public static final String KEY_DELTACRL_INTERVALS = "deltaCRL.intervals";

    public static final String KEY_OVERLAP_MINUTES = "overlap.minutes";

    public static final String KEY_INTERVAL_MINUTES = "interval.minutes";

    public static final String KEY_INTERVAL_TIME = "interval.time";

    public static final String KEY_FULLCRL_EXTENDED_NEXTUPDATE = "fullCRL.extendedNextUpdate";

    public static final String KEY_ONLY_CONTAINS_USERCERTS = "onlyContainsUserCerts";

    public static final String KEY_ONLY_CONTAINS_CACERTS = "onlyContainsCACerts";

    public static final String KEY_EXCLUDE_REASON = "excludeReason";

    public static final String KEY_INVALIDITY_DATE = "invalidityDate";

    private static final long serialVersionUID = 1L;

    private UpdateMode updateMode = UpdateMode.interval;

    private boolean xipkiCertsetIncluded;

    private boolean xipkiCertsetCertIncluded = true;

    private boolean xipkiCertsetProfilenameIncluded = true;

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

    public CrlControl(
            final String conf)
    throws InvalidConfException {
        ConfPairs props;
        try {
            props = new ConfPairs(conf);
        } catch (RuntimeException ex) {
            throw new InvalidConfException(ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }

        String str = props.getValue(KEY_UPDATE_MODE);
        if (str == null) {
            this.updateMode = UpdateMode.interval;
        } else {
            this.updateMode = UpdateMode.getUpdateMode(str);
            if (this.updateMode == null) {
                throw new InvalidConfException("invalid " + KEY_UPDATE_MODE + ": " + str);
            }
        }

        str = props.getValue(KEY_INVALIDITY_DATE);
        if (str != null) {
            this.invalidityDateMode = TripleState.fromValue(str);
        }

        this.includeExpiredCerts = getBoolean(props, KEY_EXPIRED_CERTS_INCLUDED, false);

        this.xipkiCertsetIncluded = getBoolean(props, KEY_XIPKI_CERTSET, false);

        this.xipkiCertsetCertIncluded = getBoolean(props, KEY_XIPKI_CERTSET_CERTS, true);

        this.xipkiCertsetProfilenameIncluded = getBoolean(props,
                KEY_XIPKI_CERTSET_PROFILENAME, true);

        str = props.getValue(KEY_EYTENSIONS);
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

        if (this.updateMode != UpdateMode.onDemand) {
            this.fullCrlIntervals = getInteger(props, KEY_FULLCRL_INTERVALS, 1);
            this.deltaCrlIntervals = getInteger(props, KEY_DELTACRL_INTERVALS, 0);
            this.extendedNextUpdate = getBoolean(props, KEY_FULLCRL_EXTENDED_NEXTUPDATE, false);
            this.overlapMinutes = getInteger(props, KEY_OVERLAP_MINUTES, 60);
            str = props.getValue(KEY_INTERVAL_TIME);
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
                    throw new InvalidConfException("invalid " + KEY_INTERVAL_TIME + ": '"
                            + str + "'");
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
        if (updateMode != UpdateMode.onDemand) {
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
        return getConf();
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

    public boolean isXipkiCertsetProfilenameIncluded() {
        return xipkiCertsetProfilenameIncluded;
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

    public void validate()
    throws InvalidConfException {
        if (onlyContainsCaCerts && onlyContainsUserCerts) {
            throw new InvalidConfException(
                    "onlyContainsCACerts and onlyContainsUserCerts can not be both true");
        }

        if (updateMode == UpdateMode.onDemand) {
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
    public boolean equals(
            final Object obj) {
        if (!(obj instanceof CrlControl)) {
            return false;
        }

        CrlControl obj2 = (CrlControl) obj;
        if (deltaCrlIntervals != obj2.deltaCrlIntervals
                || xipkiCertsetIncluded != obj2.xipkiCertsetIncluded
                || xipkiCertsetCertIncluded != obj2.xipkiCertsetCertIncluded
                || xipkiCertsetProfilenameIncluded != obj2.xipkiCertsetProfilenameIncluded
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

    private static int getInteger(
            final ConfPairs props,
            final String propKey,
            final int dfltValue)
    throws InvalidConfException {
        String str = props.getValue(propKey);
        if (str != null) {
            try {
                return Integer.parseInt(str.trim());
            } catch (NumberFormatException ex) {
                throw new InvalidConfException(propKey + " does not have numeric value: " + str);
            }
        }
        return dfltValue;
    }

    private static boolean getBoolean(
            final ConfPairs props,
            final String propKey,
            final boolean dfltValue)
    throws InvalidConfException {
        String str = props.getValue(propKey);
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
