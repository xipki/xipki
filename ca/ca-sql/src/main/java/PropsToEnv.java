import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.util.Properties;


public class PropsToEnv {

	public static void main(String[] args) {
		try{
			String source = args[0];
			String target = args[1];
			BufferedWriter bw = new BufferedWriter(new FileWriter(target));
			
			Properties props = new Properties();
			props.load(new FileInputStream(source));
			
			String urlKey = "db.url";			
			String jdbcUrl = props.getProperty(urlKey);
			if(jdbcUrl == null)
			{
				urlKey = "jdbcUrl";
				jdbcUrl = props.getProperty(urlKey);
			}
			
			if(jdbcUrl != null && jdbcUrl.startsWith("jdbc:db2:"))
			{
				String sep = ":currentSchema=";
				int idx = jdbcUrl.indexOf(sep);
				if(idx != -1)
				{
					String schema = jdbcUrl.substring(idx + sep.length());
					if(schema.endsWith(";"))
					{
						schema =schema.substring(0, schema.length() - 1);
					}
					jdbcUrl = jdbcUrl.substring(0, idx);
					props.setProperty(urlKey, jdbcUrl);
					props.setProperty("schema", schema);
				}
			}			
			
			for(Object okey : props.keySet())
			{
				String key = (String) okey;
				bw.write(key.replace('.', '_'));
				bw.write("=");
				bw.write(props.getProperty(key));
				bw.write("\n");				
			}
			bw.close();			
		}catch(Exception e)
		{
			e.printStackTrace();
			System.exit(-1);
		}
	}

}
