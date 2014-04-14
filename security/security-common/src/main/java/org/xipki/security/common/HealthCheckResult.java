package org.xipki.security.common;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class HealthCheckResult {
	private boolean healthy = false;
	private Map<String, Object> statuses = new ConcurrentHashMap<String, Object>();
	
	public HealthCheckResult() {
	}

	public void setHealthy(boolean healthy) {
		this.healthy = healthy;
	}

	public void cleanStatuses()
	{
		this.statuses.clear();
	}
	
	public void putStatus(String statusName, Object statusValue) {
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
	
	public boolean isHealthy() {
		return healthy;
	}

	public Map<String, Object> getStatuses() {
		return Collections.unmodifiableMap(statuses);
	}
	
	public String toJsonMessage(boolean pretty)
	{
		StringBuilder sb = new StringBuilder();
		sb.append("{\"healthcheck\" : {");
		
		Set<String> names = statuses.keySet();
		if(names.isEmpty() == false)
		{
			for(String name : names)
			{
				append(sb, name, statuses.get(name), pretty);
			}
			sb.deleteCharAt(sb.length()-1); // delete the last comma
		}
		
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
		sb.append("\"").append(name).append("\": ");
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
		checkResult.putStatus("boolean-true", true);
		checkResult.putStatus("boolean-false", false);
		checkResult.putStatus("string", "hello");
		checkResult.putStatus("long", Long.valueOf(100));
		checkResult.putStatus("int", Integer.valueOf(100));
		checkResult.putStatus("Double", Double.valueOf(100.1));
		System.out.println(checkResult.toJsonMessage(true));
		
		
		System.out.println(checkResult.toJsonMessage(false));
		
	}
}
