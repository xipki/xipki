/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.security.common;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class HealthCheckResult
{
    private boolean healthy = false;
    private Map<String, Object> statuses = new ConcurrentHashMap<String, Object>();

    public HealthCheckResult()
    {
    }

    public void setHealthy(boolean healthy)
    {
        this.healthy = healthy;
    }

    public void cleanStatuses()
    {
        this.statuses.clear();
    }

    public void putStatus(String statusName, Object statusValue)
    {
        this.statuses.put(statusName, statusValue);
    }

    public Object getStatus(String statusName)
    {
        return statusName == null ? null : statuses.get(statusName);
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
        StringBuilder sb = new StringBuilder();
        sb.append("{\"healthcheck\":{");
        append(sb, "healthy", healthy, pretty);

        String message = null;
        Set<String> names = statuses.keySet();
        if(names == null || names.isEmpty() == false)
        {
            StringBuilder msgBuilder = new StringBuilder();

            for(String name : names)
            {
                msgBuilder.append(name).append(": ").append(statuses.get(name));
                msgBuilder.append(", ");
            }
            message = msgBuilder.substring(0, msgBuilder.length() - 2);
        }

        if(message != null)
        {
            append(sb, "message", message.toString(), pretty);
        }

        sb.deleteCharAt(sb.length()-1);
        if(pretty)
        {
            sb.append("\n");
        }
        sb.append("}}");
        return sb.toString();
    }

    private static void append(StringBuilder sb, String name, Object value, boolean pretty)
    {
        if(pretty)
        {
            sb.append("\n  ");
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
        sb.append(",");
    }

    public static void main(String[] args)
    {
        HealthCheckResult checkResult = new HealthCheckResult();
        checkResult.setHealthy(false);
        checkResult.putStatus("boolean-true", true);
        checkResult.putStatus("boolean-false", false);
        checkResult.putStatus("string", "hello");
        checkResult.putStatus("long", Long.valueOf(100));
        checkResult.putStatus("int", Integer.valueOf(100));
        checkResult.putStatus("Double", Double.valueOf(100.1));
        System.out.println(checkResult.toJsonMessage(true));


        System.out.println(checkResult.toJsonMessage(false));

        checkResult = new HealthCheckResult();
        checkResult.setHealthy(true);
        System.out.println(checkResult.toJsonMessage(true));
        System.out.println(checkResult.toJsonMessage(false));


    }
}
