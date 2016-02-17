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

package org.xipki.security.common;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Lijun Liao
 */

public class HealthCheckResult
{
    private String name;
    private boolean healthy = false;
    private Map<String, Object> statuses = new ConcurrentHashMap<>();
    private List<HealthCheckResult> childChecks = new LinkedList<>();

    /**
     * Name of the check result
     * @param name
     */
    public HealthCheckResult(String name)
    {
        ParamChecker.assertNotEmpty("name", name);
        this.name = name;
    }

    public void setHealthy(boolean healthy)
    {
        this.healthy = healthy;
    }

    public void clearStatuses()
    {
        this.statuses.clear();
    }

    public Object getStatus(String statusName)
    {
        return statusName == null ? null : statuses.get(statusName);
    }

    public void clearChildChecks()
    {
        this.childChecks.clear();
    }

    public void addChildCheck(HealthCheckResult childCheck)
    {
        this.childChecks.add(childCheck);
    }

    public Set<String> getStatusNames()
    {
        return statuses.keySet();
    }

    public boolean isHealthy()
    {
        return healthy;
    }

    public Map<String, Object> getStatuses()
    {
        return Collections.unmodifiableMap(statuses);
    }

    public String toJsonMessage(boolean pretty)
    {
        return toJsonMessage(0, pretty);
    }

    private String toJsonMessage(int level, boolean pretty)
    {
        // Non root check requires always a name
        StringBuilder sb = new StringBuilder();
        if(pretty)
        {
            sb.append(getIndent(level));
        }
        if(level > 0)
        {
            sb.append("\"").append(name).append("\":");
        }
        sb.append("{");

        boolean lastElement = true;
        if(lastElement && statuses.isEmpty() == false)
        {
            lastElement = false;
        }
        if(lastElement && childChecks.isEmpty() == false)
        {
            lastElement = false;
        }
        append(sb, "healthy", healthy, level + 1,pretty, lastElement);

        Set<String> names = statuses.keySet();
        int size = names.size();
        int count = 0;
        for(String name : names)
        {
            count++;
            append(sb, name, statuses.get(name), level + 1, pretty, childChecks.isEmpty() && count == size);
        }

        if(childChecks.isEmpty() == false)
        {
            if(pretty)
            {
                sb.append("\n");
                sb.append(getIndent(level + 1));
            }

            sb.append("\"checks\":{");
            if(pretty)
            {
                sb.append("\n");
            }

            int n = childChecks.size();
            for(int i = 0; i < n; i++)
            {
                HealthCheckResult childCheck = childChecks.get(i);
                if(i > 0)
                {
                    sb.append("\n");
                }
                sb.append(childCheck.toJsonMessage(level + 2, pretty));
                if(i < n - 1)
                {
                    sb.append(",");
                }
            }

            if(pretty)
            {
                sb.append("\n");
                sb.append(getIndent(level + 1));
            }
            sb.append("}");
        }

        if(pretty)
        {
            sb.append("\n");
            sb.append(getIndent(level));
        }
        sb.append("}");
        return sb.toString();
    }

    private static void append(StringBuilder sb, String name, Object value, int level, boolean pretty, boolean lastElement)
    {
        if(pretty)
        {
            sb.append("\n");
            sb.append(getIndent(level));
        }
        sb.append("\"").append(name).append("\":");
        if(value == null)
        {
            sb.append("null");
        }
        else if(value instanceof Number)
        {
            sb.append(value);
        }
        else if(value instanceof Boolean)
        {
            sb.append(value);
        }
        else
        {
            sb.append("\"").append(value).append("\"");
        }
        if(lastElement == false)
        {
            sb.append(",");
        }
    }

    private static String getIndent(int level)
    {
        if(level == 0)
        {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < level; i++)
        {
            sb.append("  ");
        }
        return sb.toString();
    }
    /*
    public static void main(String[] args)
    {
        HealthCheckResult checkResult = new HealthCheckResult("mycheck-negative");
        checkResult.setHealthy(false);
        checkResult.putStatus("boolean-true", true);
        checkResult.putStatus("boolean-false", false);
        checkResult.putStatus("string", "hello");
        checkResult.putStatus("long", Long.valueOf(100));
        checkResult.putStatus("int", Integer.valueOf(100));
        checkResult.putStatus("Double", Double.valueOf(100.1));

        System.out.println();
        System.out.println(checkResult.toJsonMessage(true));

        System.out.println();
        System.out.println(checkResult.toJsonMessage(false));

        checkResult = new HealthCheckResult("mycheck-positive");
        checkResult.setHealthy(true);

        System.out.println();
        System.out.println(checkResult.toJsonMessage(true));

        System.out.println();
        System.out.println(checkResult.toJsonMessage(false));

        HealthCheckResult childCheck = new HealthCheckResult("childcheck");
        checkResult.addChildCheck(childCheck);
        childCheck.setHealthy(false);
        childCheck.putStatus("boolean-true", true);
        childCheck.putStatus("boolean-false", false);

        HealthCheckResult childCheck2 = new HealthCheckResult("childcheck2");
        checkResult.addChildCheck(childCheck2);
        childCheck.setHealthy(false);
        childCheck.putStatus("boolean-true", true);
        childCheck.putStatus("boolean-false", false);

        HealthCheckResult childChildCheck = new HealthCheckResult("childChildCheck");
        childCheck.addChildCheck(childChildCheck);
        childChildCheck.setHealthy(false);
        childChildCheck.putStatus("boolean-true", true);
        childChildCheck.putStatus("boolean-false", false);

        System.out.println();
        System.out.println(checkResult.toJsonMessage(true));

        System.out.println();
        System.out.println(checkResult.toJsonMessage(false));
    }*/
}
