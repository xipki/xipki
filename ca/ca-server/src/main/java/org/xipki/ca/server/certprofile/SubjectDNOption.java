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

package org.xipki.ca.server.certprofile;

import java.util.List;
import java.util.regex.Pattern;

import org.xipki.security.common.EnvironmentParameterResolver;

/**
 * @author Lijun Liao
 */

class SubjectDNOption
{
    private final List<AddText> addprefixes;
    private final List<AddText> addsufixes;
    private final Pattern pattern;

    public SubjectDNOption(List<AddText> addprefixes, List<AddText> addsufixes, Pattern pattern)
    {
        this.addprefixes = addprefixes;
        this.addsufixes = addsufixes;
        this.pattern = pattern;
    }

    public AddText getAddprefix(EnvironmentParameterResolver pr)
    {
        return getAddText(addprefixes, pr);
    }

    public AddText getAddsufix(EnvironmentParameterResolver pr)
    {
        return getAddText(addsufixes, pr);
    }

    private static AddText getAddText(List<AddText> list, EnvironmentParameterResolver pr)
    {
        if(list == null || list.isEmpty())
        {
            return null;
        }

        for(AddText e : list)
        {
            if(e.getCondition() == null)
            {
                return e;
            }

            Condition c = e.getCondition();

            if(c.satisfy(pr))
            {
                return e;
            }
        }

        return null;
    }

    public Pattern getPattern()
    {
        return pattern;
    }

}
