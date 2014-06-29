#!/bin/sh

if [ "$LIQUIBASE_HOME" = "" ]; then
  echo "LIQUIBASE_HOME is not set."
  exit
fi

if [ "$XIPKI_HOME" = "" ]; then
  echo "XIPKI_HOME is not set."
  exit
fi

# Log level of liquibase: debug, info, warning, severe, off
LOG_LEVEL=off

COMMAND=$1
PROP_FILE=$2
CHANGELOG_FILE=$3

JDBC_CP=$( echo $XIPKI_HOME/lib/ext/*.jar | sed 's/ /:/g')

# retrieve the database configuration
java -cp $LIQUIBASE_HOME/.. PropsToEnv $PROP_FILE .tmp-db.properties
. ./.tmp-db.properties
rm -f .tmp-db.properties

SCHEMA=""
DRIVER=""
USER=""
PASSWORD=""
URL=""

if [ "$dataSourceClassName" != "" ]; then
    if [ "$dataSourceClassName" = "org.h2.jdbcx.JdbcDataSource" ]; then
       DRIVER="org.h2.Driver"
       URL="$dataSource_url"
    elif [ "$dataSourceClassName" = "com.mysql.jdbc.jdbc2.optional.MysqlDataSource" ]; then
       DRIVER="com.mysql.jdbc.Driver"
       URL="jdbc:mysql://$dataSource_serverName:$dataSource_port/$dataSource_databaseName"
    elif [ "$dataSourceClassName" = "oracle.jdbc.pool.OracleDataSource" ]; then
       DRIVER="oracle.jdbc.driver.OracleDriver"
       URL="jdbc:oracle:thin:@$dataSource_serverName:$dataSource_portNumber:$dataSource_databaseName"
    elif [ "$dataSourceClassName" = "com.ibm.db2.jcc.DB2SimpleDataSource" ]; then
       DRIVER="com.ibm.db2.jcc.DB2Driver"
       URL="jdbc:db2://$dataSource_serverName:$dataSource_portNumber/$dataSource_databaseName"
       SCHEMA="$dataSource_currentSchema"
    elif [ "$dataSourceClassName" = "com.impossibl.postgres.jdbc.PGDataSource" ]; then
       DRIVER="com.impossibl.postgres.jdbc.PGDriver"
       URL="jdbc:pgsql://$dataSource_host:$dataSource_port/$dataSource_database"
    elif [ "$dataSourceClassName" = "net.sourceforge.jtds.jdbcx.JtdsDataSource" ]; then
       DRIVER="net.sourceforge.jtds.jdbc.Driver"     
       if [ "$dataSource_serverType" = "2" ]; then
           JTDS_SERVERTYPE="sybase"
       else
           JTDS_SERVERTYPE="sqlserver"
       fi
       URL="jdbc:jtds:$JTDS_SERVERTYPE://$dataSource_serverName:$dataSource_portNumber/$dataSource_databaseName"
    else
       echo "Unknown dataSourceClassName: $db_dataSourceClassName"
       exit
    fi

    USER="$dataSource_user"
    PASSWORD="$dataSource_password"
else
    if [ "$driverClassName" != "" ]; then
        DRIVER="$driverClassName"
        USER="$username"
        PASSWORD="$password"
        URL="$jdbcUrl"
    elif [ "$db_driverClassName" != "" ]; then
        DRIVER="$db_driverClassName"
        USER="$db_username"
        PASSWORD="$db_password"
        URL="$db_url"
    else
       echo "Unknown configuration"
       exit
    fi

    SCHEMA="$schema"
fi

echo "DRIVER     = $DRIVER"
echo "USER       = $USER"
echo "URL        = $URL"
if [ "$SCHEMA" != "" ]; then
    echo "SCHEMA     = $SCHEMA"
fi
echo "CHANGELOG  = $CHANGELOG_FILE"

liquibase ()
{
   CMD="$LIQUIBASE_HOME/liquibase --driver=$DRIVER --classpath=$JDBC_CP --changeLogFile=$CHANGELOG_FILE --url=$URL --username=$USER --password=$PASSWORD --logLevel=$LOG_LEVEL"

   if [ "$SCHEMA" != "" ]; then
       CMD="$CMD --defaultSchemaName=$SCHEMA"
   fi

   CMD="$CMD $COMMAND"
   #echo "$CMD"
   $CMD
}

if [ $# = 3 ]; then
  while true; do
    read -p "Do you wish to $COMMAND database [yes/no] ? " RESP
    if [ "$RESP" = "yes" ]; then
       liquibase
       break
    elif [ "$RESP" = "no" ]; then
       break
    else
       echo "Please answer with yes or no"
    fi
  done
else
  echo 'Usage: '
  echo   'ca-db.sh <command> <database conf file> <changlog file>'
  echo  ''
  echo  'Command:'
  echo     update
  echo     dropAll
  echo     releaseLocks
fi

