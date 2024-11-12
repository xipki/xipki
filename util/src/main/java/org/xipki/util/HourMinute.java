// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

/**
 * Specifies hour:minute.
 *
 * @author Lijun Liao (xipki)
 */
public class HourMinute {

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
