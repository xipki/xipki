/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.common;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.xipki.common.util.CollectionUtil;

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
    public HealthCheckResult(
            final String name)
    {
        ParamChecker.assertNotBlank("name", name);
        this.name = name;
    }

    public void setHealthy(
            final boolean healthy)
    {
        this.healthy = healthy;
    }

    public void clearStatuses()
    {
        this.statuses.clear();
    }

    public Object getStatus(
            final String statusName)
    {
        return statusName == null ? null : statuses.get(statusName);
    }

    public void clearChildChecks()
    {
        this.childChecks.clear();
    }

    public void addChildCheck(
            final HealthCheckResult childCheck)
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

    public String toJsonMessage(
            final boolean pretty)
    {
        return toJsonMessage(0, pretty);
    }

    private String toJsonMessage(
            final int level,
            final boolean pretty)
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
        if(lastElement && CollectionUtil.isNotEmpty(statuses))
        {
            lastElement = false;
        }
        if(lastElement && CollectionUtil.isNotEmpty(childChecks))
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
            append(sb, name, statuses.get(name), level + 1, pretty,
                    CollectionUtil.isEmpty(childChecks) && count == size);
        }

        if(CollectionUtil.isNotEmpty(childChecks))
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

    private static void append(
            final StringBuilder sb,
            final String name,
            final Object value,
            final int level,
            final boolean pretty,
            final boolean lastElement)
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

    private static String getIndent(
            final int level)
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

    public static HealthCheckResult getInstanceFromJsonMessage(
            final String name,
            final String jsonMessage)
    {
        // remove white spaces and line breaks
        String jsonMsg = jsonMessage.replaceAll(" |\t|\r|\n", "");
        if(jsonMsg.startsWith("{\"healthy\":") == false)
        {
            throw new IllegalArgumentException("invalid healthcheck message");
        }

        int startIdx = "{\"healthy\":".length();
        int endIdx = jsonMsg.indexOf(',', startIdx);
        boolean containsChildChecks = true;
        if(endIdx == -1)
        {
            endIdx = jsonMsg.indexOf('}', startIdx);
            containsChildChecks = false;
        }

        if(endIdx == -1)
        {
            throw new IllegalArgumentException("invalid healthcheck message");
        }

        String s = jsonMsg.substring(startIdx, endIdx);

        boolean healthy;
        if(s.equalsIgnoreCase("true") || s.equalsIgnoreCase("false"))
        {
            healthy = Boolean.parseBoolean(s);
        }
        else
        {
            throw new IllegalArgumentException("invalid healthcheck message");
        }

        HealthCheckResult result = new HealthCheckResult(name);
        result.setHealthy(healthy);

        if(containsChildChecks == false)
        {
            return result;
        }

        if(jsonMsg.startsWith("\"checks\":", endIdx + 1) == false)
        {
            return result;
        }

        String checksBlock = getBlock(jsonMsg, endIdx + 1 + "\"checks\":".length());
        Map<String, String> childBlocks = getChildBlocks(checksBlock.substring(1, checksBlock.length() - 1));
        for(String childBlockName : childBlocks.keySet())
        {
            HealthCheckResult childResult = getInstanceFromJsonMessage(childBlockName, childBlocks.get(childBlockName));
            result.addChildCheck(childResult);
        }

        return result;
    }

    private static Map<String, String> getChildBlocks(
            final String block)
    {
        Map<String, String> childBlocks = new HashMap<>();

        int offset = 0;
        while(true)
        {
            int idx = block.indexOf('"', offset + 1);
            String blockName = block.substring(offset + 1, idx);
            String blockValue = getBlock(block, offset + blockName.length() + 3);
            childBlocks.put(blockName, blockValue);

            offset += blockName.length() + 4 + blockValue.length();
            if(offset >=  block.length() - 1)
            {
                break;
            }
        }

        return childBlocks;
    }

    private static String getBlock(
            final String text,
            final int offset)
    {
        if(text.startsWith("{", offset) == false)
        {
            throw new IllegalArgumentException("invalid text: '" + text + "'");
        }

        StringBuilder sb = new StringBuilder("{");
        final int n = text.length();
        if(n < 2)
        {
            throw new IllegalArgumentException("invalid text: '" + text + "'");
        }

        char c;
        int m = 0;
        for(int i = offset + 1; i < n; i++)
        {
            c = text.charAt(i);
            sb.append(c);

            if(c == '{')
            {
                m++;
            }
            else if(c == '}')
            {
                if(m == 0)
                {
                    return sb.toString();
                }
                else
                {
                    m--;
                }
            } // end if
        } // end for

        throw new IllegalArgumentException("invalid text: '" + text + "'");
    }

    public static void main(
            final String[] args)
    {
        String jm1 = "{\"healthy\":true}";
        String jm2 = "{\"healthy\":true,\"checks\":{\"childcheck\":{\"healthy\":false,"
                + "\"checks\":{\"childChildCheck\":{\"healthy\":false}}},\"childcheck2\":{\"healthy\":false}}}";
        System.out.println(getBlock(jm1,0));
        System.out.println(getBlock(jm2, 25));
        getInstanceFromJsonMessage("default", jm1);
        getInstanceFromJsonMessage("default", jm2);

        HealthCheckResult checkResult = new HealthCheckResult("mycheck-negative");
        checkResult.setHealthy(false);

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

        HealthCheckResult childCheck2 = new HealthCheckResult("childcheck2");
        checkResult.addChildCheck(childCheck2);
        childCheck.setHealthy(false);

        HealthCheckResult childChildCheck = new HealthCheckResult("childChildCheck");
        childCheck.addChildCheck(childChildCheck);
        childChildCheck.setHealthy(false);

        System.out.println();
        System.out.println(checkResult.toJsonMessage(true));

        System.out.println();
        System.out.println(checkResult.toJsonMessage(false));
    }
}
