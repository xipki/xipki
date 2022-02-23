/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.util;

/**
 * Specifies hour:minute.
 *
 * @author Lijun Liao
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
