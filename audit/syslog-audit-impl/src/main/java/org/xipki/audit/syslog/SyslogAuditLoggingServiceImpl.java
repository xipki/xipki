package org.xipki.audit.syslog;

import java.nio.charset.Charset;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditEventDataType;
import org.xipki.audit.api.AuditLoggingService;
import org.xipki.audit.api.PCIAuditEvent;

import com.nesscomputing.syslog4j.Syslog;
import com.nesscomputing.syslog4j.SyslogConfigIF;
import com.nesscomputing.syslog4j.SyslogFacility;
import com.nesscomputing.syslog4j.SyslogIF;
import com.nesscomputing.syslog4j.SyslogLevel;
import com.nesscomputing.syslog4j.SyslogRuntimeException;
import com.nesscomputing.syslog4j.impl.AbstractSyslogConfigIF;
import com.nesscomputing.syslog4j.impl.message.modifier.sequential.SequentialSyslogMessageModifier;
import com.nesscomputing.syslog4j.impl.message.pci.PCISyslogMessage;
import com.nesscomputing.syslog4j.util.SyslogUtility;

public class SyslogAuditLoggingServiceImpl implements AuditLoggingService
{ 
    private static final Logger LOG = LoggerFactory.getLogger(SyslogAuditLoggingServiceImpl.class);
    private static final DateFormat df = new SimpleDateFormat("yyyy.MM.dd '-' HH:mm:ss.SSS z");

    /**
     * The default port is 514.
     */
    public static final int    DEFAULT_SYSLOG_PORT = 514;
    /**
     * The default mode is TCP.
     */
    public static final String DEFAULT_SYSLOG_PROTOCOL = "tcp";
    /**
     * The default facility is USER.
     */
    public static final String  DEFAULT_SYSLOG_FACILITY = "user";
    /**
     * The default ip is localhost.
     */
    public static final String DEFAULT_SYSLOG_HOST = "localhost";
    
    /**
     * The syslog4j client instance 
     */
    protected SyslogIF syslog = null;
    
    private String host = DEFAULT_SYSLOG_HOST;
    private int port = DEFAULT_SYSLOG_PORT;
    private String protocol = DEFAULT_SYSLOG_PROTOCOL;
    private String facility = DEFAULT_SYSLOG_FACILITY;
    
    private boolean               useThreading            = false;
    private boolean               useStructuredData       = false;
    private boolean               useSequenceNumbers      = false;
    private boolean               truncateMessage         = false;

    private int                   threadLoopInterval;
    private int                   writeRetries;
    private int                   maxMessageLength;
    private int                   maxShutdownWait;

    private String                ident                   = null;
    private String                localName               = null;
    private String                charSet                 = null;
    private String                splitMessageBeginText   = null;
    private String                splitMessageEndText     = null;

    protected boolean             initialized             = false;
    
    
    public SyslogAuditLoggingServiceImpl() 
    {
    }
    
    @Override
    public void logEvent(final AuditEvent event) 
    {   
    	if(event == null)
    	{
    		return;
    	}
    	init();

        syslog.log(SyslogLevel.forValue(event.getLevel().getValue()), loggingCompatibleEvent(event));
    }

    public void logEvent(final PCIAuditEvent event)
    {
    	if(event == null)
    	{
    		return;
    	}
    	init();
    	
        PCISyslogMessage pciMessage = new PCISyslogMessage();        
        pciMessage.setUserId(event.getUserId());
        pciMessage.setDate(event.getDate());
        pciMessage.setTime(event.getTime());
        pciMessage.setEventType(event.getEventType());
        pciMessage.setOrigination(event.getOrigination());
        pciMessage.setStatus(event.getStatus());
        pciMessage.setAffectedResource(event.getAffectedResource());
        
        this.syslog.log(SyslogLevel.forValue(event.getLevel().getValue()), pciMessage);
    }

    /**
     * The event to be logged has to be transformed to a human readable format.
     * 
     * @param event
     *            The event to be transformed.
     * @return The string representation of the event.
     */
    private String loggingCompatibleEvent(final AuditEvent event)
    {
        StringBuilder sb = new StringBuilder();
        sb.append(event.getApplicationName()).append(" - ").append(event.getName());
        
        AuditEventData[] eventDataArray = event.getEventDatas();
        
        if ((eventDataArray != null) && (eventDataArray.length > 0))
        {
            sb.append(":");
            
            for (AuditEventData element : eventDataArray)
            {
                sb.append("\t");
                sb.append(element.getName());
                sb.append(": ");

                AuditEventDataType eventDataType = element.getEventDataType();
                switch(eventDataType)
                {
                case BINARY:
                    sb.append(getHexString(element.getBinaryValue()));
                    break;
                case NUMBER:
                    sb.append(element.getNumberValue());
                    break;
                case TEXT:
                    sb.append(element.getTextValue());
                    break;
                case TIMESTAMP:
                    sb.append(df.format(element.getTimestampValue()));
                    break;
                }
            }
        }
        return sb.toString();
    }
     
    public void init()
    {        
    	if(initialized)
    	{
    		return;
    	}
    	
        LOG.info("Initializing: {}", SyslogAuditLoggingServiceImpl.class);      

        try
        {
            syslog = Syslog.getInstance(this.protocol);
            SyslogConfigIF config = syslog.getConfig();
            
            if (notEmpty(host))
            {
                config.setHost(host);
            }
            config.setPort(port);

            if (notEmpty(facility))
            {
            	SyslogFacility sysFacility = SyslogFacility.valueOf(facility);
            	if(sysFacility != null)
            	{
            		config.setFacility(sysFacility);
            	}
            }
            
            if (notEmpty(charSet))
            {
                this.syslog.getConfig().setCharSet(Charset.forName(charSet));
            }

            if (notEmpty(ident))
            {
                config.setIdent(ident);
            }

            if (notEmpty(localName))
            {
                config.setLocalName(this.localName);
            }

            config.setTruncateMessage(truncateMessage);
            config.setMaxMessageLength(maxMessageLength);

            config.setUseStructuredData(useStructuredData);
             
            if (useSequenceNumbers)
            {
                SequentialSyslogMessageModifier sequentialModifier = SequentialSyslogMessageModifier.createDefault();
                config.addMessageModifier(sequentialModifier);
            }
            
            if (config instanceof AbstractSyslogConfigIF)
            {
                AbstractSyslogConfigIF abstractSyslogConfig = (AbstractSyslogConfigIF) config;

                abstractSyslogConfig.setThreaded(useThreading);

                if (threadLoopInterval > 0)
                {
                    abstractSyslogConfig.setThreadLoopInterval(threadLoopInterval);
                }

                if (splitMessageBeginText != null)
                {
                    abstractSyslogConfig.setSplitMessageBeginText(
                    		SyslogUtility.getBytes(abstractSyslogConfig, splitMessageBeginText));
                }

                if (splitMessageEndText != null)
                {
                    abstractSyslogConfig.setSplitMessageEndText(
                    		SyslogUtility.getBytes(abstractSyslogConfig, splitMessageEndText));
                }

                if (maxShutdownWait > 0)
                {
                    abstractSyslogConfig.setMaxShutdownWait(maxMessageLength);
                }

                if (writeRetries > 0)
                {
                    abstractSyslogConfig.setWriteRetries(writeRetries);
                }
            }

            // after we're finished set initialized to true
            this.initialized = true;
            LOG.info("Initialized: {}", SyslogAuditLoggingServiceImpl.class);      
        }
        catch (SyslogRuntimeException sre)
        {
            LOG.error(sre.toString());
        }
        
    }
    
    public void destroy()
    {
        LOG.info("Destroying: {}", SyslogAuditLoggingServiceImpl.class);
        try
        {         
            if (syslog != null)
            {              
                syslog.flush();
                syslog.getConfig().removeAllMessageModifiers();
                syslog.shutdown();
            }
            LOG.info("Destroyed: {}", SyslogAuditLoggingServiceImpl.class);
        }
        catch (SyslogRuntimeException sre)
        {
            LOG.warn("during destroy/close",sre);
        }
    }

    public void setFacility(String facility)
    {
        this.facility = facility;
    }

    public void setCharSet(String charSet)
    {
        this.charSet = charSet;
    }

    public void setHost(String host)
    {
        this.host = host;
    }
    
    public void setPort(int port)
    {
        this.port = port;
    }

    public void setProtocol(String protocol)
    {
        this.protocol = protocol;
    }

    public void setIdent(String ident)
    {
        this.ident = ident;
    }

    public void setUseThreading(boolean useThreading)
    {
        this.useThreading = useThreading;
    }

    public void setThreadLoopInterval(int threadLoopInterval)
    {
        this.threadLoopInterval = threadLoopInterval;
    }

    public void setWriteRetries(int writeRetries)
    {
        this.writeRetries = writeRetries;
    }

    public void setUseStructuredData(boolean useStructuredData)
    {
        this.useStructuredData = useStructuredData;
    }

    public void setUseSequenceNumbers(boolean useSequenceNumbers)
    {
        this.useSequenceNumbers = useSequenceNumbers;
    }

    public void setLocalName(String localName)
    {
        this.localName = localName;
    }

    public void setSplitMessageBeginText(String splitMessageBeginText)
    {
        this.splitMessageBeginText = splitMessageBeginText;
    }

    public void setSplitMessageEndText(String splitMessageEndText)
    {
        this.splitMessageEndText = splitMessageEndText;
    }

    public void setMaxMessageLength(int maxMessageLength)
    {
        if ( maxMessageLength <= 0)
        {
            maxMessageLength = 1023;
        }
        else
        {
            this.maxMessageLength = maxMessageLength;
        }
    }

    public void setMaxShutdownWait(int maxShutdownWait)
    {
        this.maxShutdownWait = maxShutdownWait;
    }

    public void setTruncateMessage(boolean truncateMessage)
    {
        this.truncateMessage = truncateMessage;
    }
    
    private static boolean notEmpty(String text)
    {
    	return text != null && text.isEmpty() == false;
    }
    
    private static final char[] HEX_CHAR_TABLE = "0123456789ABCDEF".toCharArray();
    private static String getHexString(final byte[] raw)
    {
    	StringBuilder sb = new StringBuilder();    	
        for (byte b : raw)
        {
        	int v = (b < 0) ? 256 + b : b;
        	sb.append(HEX_CHAR_TABLE[v >>> 4]);
        	sb.append(HEX_CHAR_TABLE[v & 0x0F]);        	
        	sb.append(" ");
        }        
        return sb.toString();
    }
}
