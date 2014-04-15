package org.xipki.audit.api;

import java.util.Arrays;
import java.util.Date;

public class AuditEventData
{
	public static final int STRING_MAX_LENGTH = 255;
    
    private final String name;

    private final AuditEventDataType eventDataType;

    private final Double numberValue;

    private final String textValue;

    private final Date timestampValue;

    private final byte[] binaryValue;

    public AuditEventData(final String name, final byte[] value)
    {
    	if(name == null || name.isEmpty())
    	{
    		throw new IllegalArgumentException("name could not be null");
    	}
    	if(value == null)
    	{
    		throw new IllegalArgumentException("value could not be null");
    	}
    	
        eventDataType = AuditEventDataType.BINARY;        
        
        this.name = name;
        this.numberValue = null;
        this.textValue = null;
        this.timestampValue = null;
        this.binaryValue = value;
    }

    public AuditEventData(final String name, final Date value)
    {
    	if(name == null || name.isEmpty())
    	{
    		throw new IllegalArgumentException("name could not be null");
    	}
    	if(value == null)
    	{
    		throw new IllegalArgumentException("value could not be null");
    	}

    	eventDataType = AuditEventDataType.TIMESTAMP;

        this.name = name;
        this.numberValue = null;
        this.textValue = null;
        this.timestampValue = value;
        this.binaryValue = null;
    }

    public AuditEventData(final String name, final Double value)
    {
    	if(name == null || name.isEmpty())
    	{
    		throw new IllegalArgumentException("name could not be null");
    	}
    	if(value == null)
    	{
    		throw new IllegalArgumentException("value could not be null");
    	}

        eventDataType = AuditEventDataType.NUMBER;
        this.name = name;
        this.numberValue = value;
        this.textValue = null;
        this.timestampValue = null;
        this.binaryValue = null;
    }

    public AuditEventData(final String name, final String value)
    {
    	if(name == null || name.isEmpty())
    	{
    		throw new IllegalArgumentException("name could not be null");
    	}
    	if(value == null)
    	{
    		throw new IllegalArgumentException("value could not be null");
    	}

        eventDataType = AuditEventDataType.TEXT;
        this.name = name;
        this.numberValue = null;
        this.textValue = value;
        this.timestampValue = null;
        this.binaryValue = null;
    }

    public AuditEventDataType getEventDataType()
    {
        return eventDataType;
    }

    public String getName()
    {
        return name;
    }

    public Double getNumberValue()
    {
        return numberValue;
    }

    public String getTextValue()
    {
        return textValue;
    }

    public Date getTimestampValue()
    {
        return timestampValue;
    }

    public byte[] getBinaryValue()
    {
        return Arrays.copyOf(binaryValue, binaryValue.length);
    }

}
