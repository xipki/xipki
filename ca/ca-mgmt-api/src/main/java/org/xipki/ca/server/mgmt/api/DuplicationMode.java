/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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

package org.xipki.ca.server.mgmt.api;

/**
 * @author Lijun Liao
 */

public enum DuplicationMode
{
    FORBIDDEN (1, "forbidden"),
    FORBIDDEN_WITHIN_PROFILE (2, "forbiddenWithinProfile"),
    PERMITTED (3, "permitted");

    private final int mode;
    private final String description;

    private DuplicationMode(int mode, String description)
    {
        this.mode = mode;
        this.description = description;
    }

    public int getMode()
    {
        return mode;
    }

    public String getDescription()
    {
        return description;
    }

    public static DuplicationMode getInstance(String text)
    {
        for(DuplicationMode value : values())
        {
            if(value.description.equalsIgnoreCase(text) ||
                    value.name().equalsIgnoreCase(text) ||
                    Integer.toString(value.mode).equalsIgnoreCase(text))
            {
                return value;
            }
        }

        return null;
    }

    public static DuplicationMode getInstance(int mode)
    {
        for(DuplicationMode value : values())
        {
            if(mode == value.mode)
            {
                return value;
            }
        }

        return null;
    }
}
