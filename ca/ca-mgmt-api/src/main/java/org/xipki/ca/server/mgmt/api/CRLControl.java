/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.api;

import java.util.HashSet;
import java.util.Set;
import java.util.StringTokenizer;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.ConfigurationException;

/**
 *
 * Example configuration
 * updateMode?<'interval'|'onDemand'>
 *
 * # For all updateMode
 *
 * # Whether expired certificates are considered
 * expiredCerts.included?<'true'|'false'>
 *
 * # Whether certificates are embedded in CRL, XiPKI-customized extension
 * certs.embedded = <'true'|'false'>
 *
 * # List of OIDs of extensions to be embedded in CRL,
 * # Unspecified or empty extensions indicates that the CA decides.
 * extensions?<comma delimited OIDs of extensions>
 *
 * # The following settings are only for updateMode 'interval'
 *
 * # Number of intervals to generate a full CRL. Default is 1
 * # Should be greater than 0
 * fullCRL.intervals?<integer>
 *
 * # should be 0 or not greater than baseCRL.intervals. Default is 0.
 * # 0 indicates that no deltaCRL will be generated
 * deltaCRL.intervals=<integer>
 *
 * overlap.minutes?<minutes of overlap>
 *
 * # should be less than fullCRL.intervals.
 * # If activated, a deltaCRL will be generated only between two full CRLs
 * deltaCRL.intervals?<integer>
 *
 * # Exactly one of interval.minutes and interval.days should be specified
 * # Number of minutes of one interval. At least 60 minutes
 * interval.minutes=<minutes of one interval>
 *
 * # UTC time of generation of CRL, one interval covers 1 day.
 * interval.time?<updatet time (hh:mm of UTC time)>
 *
 * # Whether the nextUpdate of a fullCRL is the update time of the fullCRL
 * # Default is false
 * fullCRL.extendedNextUpdate?<'true'|'false'>
 *
 * @author Lijun Liao
 */

public class CRLControl
{
    Logger LOG = LoggerFactory.getLogger(CRLControl.class);
    public static final String KEY_updateMode = "updateMode";
    public static final String KEY_extensions = "extensions";
    public static final String KEY_expiredCerts_included = "expiredCerts.included";
    public static final String KEY_certs_embedded = "certs.embedded";
    public static final String KEY_fullCRL_intervals = "fullCRL.intervals";
    public static final String KEY_deltaCRL_intervals = "deltaCRL.intervals";
    public static final String KEY_overlap_minutes = "overlap.minutes";
    public static final String KEY_interval_minutes = "interval.minutes";
    public static final String KEY_interval_time = "interval.time";
    public static final String KEY_fullCRL_extendedNextUpdate = "fullCRL.extendedNextUpdate";

    public static enum UpdateMode
    {
        interval,
        onDemand;

        public static UpdateMode getUpdateMode(String mode)
        {
            for(UpdateMode v : values())
            {
                if(v.name().equalsIgnoreCase(mode))
                {
                    return v;
                }
            }

            return null;
        }
    }

    public static class HourMinute
    {
        private final int hour;
        private final int minute;

        public HourMinute(int hour, int minute)
        throws IllegalArgumentException
        {
            if(hour < 0 | hour > 23)
            {
                throw new IllegalArgumentException("invalid hour " + hour);
            }

            if(minute < 0 | minute > 59)
            {
                throw new IllegalArgumentException("invalid minute " + minute);
            }

            this.hour = hour;
            this.minute = minute;
        }

        public int getHour()
        {
            return hour;
        }

        public int getMinute()
        {
            return minute;
        }

        @Override
        public String toString()
        {
            StringBuilder sb = new StringBuilder();
            if(hour < 10)
            {
                sb.append("0");
            }
            sb.append(hour);
            sb.append(":");
            if(minute < 10)
            {
                sb.append("0");
            }
            sb.append(minute);
            return sb.toString();
        }
    }

    private UpdateMode updateMode = UpdateMode.interval;
    private boolean embedsCerts = false;
    private boolean includeExpiredCerts = false;
    private int fullCRLIntervals = 1;
    private int deltaCRLIntervals = 0;
    private int overlapMinutes = 10;
    private boolean extendedNextUpdate = false;
    private Integer intervalMinutes;
    private HourMinute intervalDayTime;
    private Set<String> extensionOIDs;

    public CRLControl()
    {
    }

    public static CRLControl getInstance(String conf)
    throws ConfigurationException
    {
        CmpUtf8Pairs props;
        try
        {
            props = new CmpUtf8Pairs(conf);
        }catch(RuntimeException e)
        {
            throw new ConfigurationException(e.getClass().getName() + ": " + e.getMessage(), e);
        }

        CRLControl control = new CRLControl();
        String s = props.getValue(KEY_updateMode);
        if(s != null)
        {
            UpdateMode mode = UpdateMode.getUpdateMode(s);
            if(mode == null)
            {
                throw new ConfigurationException("Invalid " + KEY_updateMode + ": " + s);
            }
            control.setUpdateMode(mode);
        }

        Boolean b = getBoolean(props, KEY_expiredCerts_included);
        if(b != null)
        {
            control.setIncludeExpiredCerts(b.booleanValue());
        }

        b = getBoolean(props, KEY_certs_embedded);
        if(b != null)
        {
            control.setEmbedsCerts(b.booleanValue());
        }

        s = props.getValue(KEY_extensions);
        if(s != null)
        {
            StringTokenizer st = new StringTokenizer(s, ", ");
            Set<String> extensionOIDs = new HashSet<>();
            while(st.hasMoreTokens())
            {
                String oidStr = st.nextToken();
                try
                {
                    new ASN1ObjectIdentifier(oidStr);
                }catch(IllegalArgumentException e)
                {
                    throw new ConfigurationException(oidStr + " is not valid OID");
                }
                extensionOIDs.add(oidStr);
            }
            control.setExtensionOIDs(extensionOIDs);
        }

        if(control.getUpdateMode() == UpdateMode.onDemand)
        {
            return control;
        }

        Integer i = getInteger(props, KEY_fullCRL_intervals);
        if(i != null)
        {
            control.setFullCRLIntervals(i.intValue());
        }

        i = getInteger(props, KEY_deltaCRL_intervals);
        if(i != null)
        {
            control.setDeltaCRLIntervals(i);
        }

        b = getBoolean(props, KEY_fullCRL_extendedNextUpdate);
        if(b != null)
        {
            control.setExtendedNextUpdate(b);
        }

        i = getInteger(props, KEY_interval_minutes);
        if(i != null)
        {
            control.setIntervalMinutes(i);
        }

        i = getInteger(props, KEY_overlap_minutes);
        if(i != null)
        {
            control.setOverlapMinutes(i);
        }

        s = props.getValue(KEY_interval_time);
        if(s != null)
        {
            StringTokenizer st = new StringTokenizer(s, ":");
            if(st.countTokens() != 2)
            {
                throw new ConfigurationException("invalid " + KEY_interval_time + ": '" + s + "'");
            }
            try
            {
                int hour = Integer.parseInt(st.nextToken());
                int minute = Integer.parseInt(st.nextToken());
                HourMinute hm = new HourMinute(hour, minute);
                control.setIntervalDayTime(hm);
            }catch(IllegalArgumentException e)
            {
                throw new ConfigurationException("invalid " + KEY_interval_time + ": '" + s + "'");
            }
        }

        control.validate();

        return control;
    }

    private static Integer getInteger(CmpUtf8Pairs props, String propKey)
    throws ConfigurationException
    {
        String s = props.getValue(propKey);
        if(s != null)
        {
            try
            {
                return Integer.parseInt(s.trim());
            }catch(NumberFormatException e)
            {
                throw new ConfigurationException(propKey + " does not have numeric value: " + s);
            }
        }
        return null;
    }

    private static Boolean getBoolean(CmpUtf8Pairs props, String propKey)
    throws ConfigurationException
    {
        String s = props.getValue(propKey);
        if(s != null)
        {
            s = s.trim();
            if("true".equalsIgnoreCase(s))
            {
                return Boolean.TRUE;
            }
            else if("false".equalsIgnoreCase(s))
            {
                return Boolean.FALSE;
            }
            else
            {
                throw new ConfigurationException(propKey + " does not have boolean value: " + s);
            }
        }
        return null;
    }

    public String getConf()
    {
        CmpUtf8Pairs pairs = new CmpUtf8Pairs();
        pairs.putUtf8Pair(KEY_updateMode, updateMode.name());
        pairs.putUtf8Pair(KEY_expiredCerts_included, Boolean.toString(includeExpiredCerts));
        pairs.putUtf8Pair(KEY_certs_embedded, Boolean.toString(embedsCerts));
        if(updateMode != UpdateMode.onDemand)
        {
            pairs.putUtf8Pair(KEY_fullCRL_intervals, Integer.toString(fullCRLIntervals));
            pairs.putUtf8Pair(KEY_fullCRL_extendedNextUpdate, Boolean.toString(extendedNextUpdate));
            pairs.putUtf8Pair(KEY_deltaCRL_intervals, Integer.toString(deltaCRLIntervals));

            if(intervalDayTime != null)
            {
                pairs.putUtf8Pair(KEY_interval_time, intervalDayTime.toString());
            }

            if(intervalMinutes != null)
            {
                pairs.putUtf8Pair(KEY_interval_minutes, intervalMinutes.toString());
            }
        }

        if(extensionOIDs != null && extensionOIDs.isEmpty() == false)
        {
            StringBuilder extensionsSb = new StringBuilder();
            for(String oid : extensionOIDs)
            {
                extensionsSb.append(oid).append(",");
            }
            extensionsSb.deleteCharAt(extensionsSb.length() - 1);
            pairs.putUtf8Pair(KEY_extensions, extensionsSb.toString());
        }

        return pairs.getEncoded();
    }

    @Override
    public String toString()
    {
        return getConf();
    }

    public UpdateMode getUpdateMode()
    {
        return updateMode;
    }

    public void setUpdateMode(UpdateMode updateMode)
    {
        this.updateMode = updateMode;
    }

    public boolean isEmbedsCerts()
    {
        return embedsCerts;
    }

    public void setEmbedsCerts(boolean embedsCerts)
    {
        this.embedsCerts = embedsCerts;
    }

    public boolean isIncludeExpiredCerts()
    {
        return includeExpiredCerts;
    }

    public void setIncludeExpiredCerts(boolean includeExpiredCerts)
    {
        this.includeExpiredCerts = includeExpiredCerts;
    }

    public int getFullCRLIntervals()
    {
        return fullCRLIntervals;
    }

    public void setFullCRLIntervals(int baseCRLIntervals)
    {
        this.fullCRLIntervals = baseCRLIntervals;
    }

    public int getDeltaCRLIntervals()
    {
        return deltaCRLIntervals;
    }

    public void setDeltaCRLIntervals(int deltaCRLIntervals)
    {
        this.deltaCRLIntervals = deltaCRLIntervals;
    }

    public int getOverlapMinutes()
    {
        return overlapMinutes;
    }

    public void setOverlapMinutes(int overlapMinutes)
    {
        this.overlapMinutes = overlapMinutes;
    }

    public Integer getIntervalMinutes()
    {
        return intervalMinutes;
    }

    public void setIntervalMinutes(Integer intervalMinutes)
    {
        if(intervalMinutes != null && intervalMinutes < 60)
        {
            LOG.warn("corrected interval.minutes from {} to {}", intervalMinutes, 60);
            this.intervalMinutes = 60;
        }
        else
        {
            this.intervalMinutes = intervalMinutes;
        }
    }

    public HourMinute getIntervalDayTime()
    {
        return intervalDayTime;
    }

    public void setIntervalDayTime(HourMinute intervalDayTime)
    {
        this.intervalDayTime = intervalDayTime;
    }

    public Set<String> getExtensionOIDs()
    {
        return extensionOIDs;
    }

    public void setExtensionOIDs(Set<String> extensionOIDs)
    {
        this.extensionOIDs = extensionOIDs;
    }

    public boolean isExtendedNextUpdate()
    {
        return extendedNextUpdate;
    }

    public void setExtendedNextUpdate(boolean extendedNextUpdate)
    {
        this.extendedNextUpdate = extendedNextUpdate;
    }

    public void validate()
    throws ConfigurationException
    {
        // TODO:validate the configuration
    }
}
