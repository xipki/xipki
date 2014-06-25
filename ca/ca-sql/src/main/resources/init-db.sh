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
cat $PROP_FILE | sed 's/\./_/' > .tmp-db.properties
. ./.tmp-db.properties
rm -f .tmp-db.properties

echo "db.driver   = $db_driverClassName"
echo "db.username = $db_username"

DRIVER=$db_driverClassName

DFLT_SCHEMA=

if [ "$DRIVER" = "com.ibm.db2.jcc.DB2Driver" ]; then
        SEP=":currentSchema="
        db_schema=${db_url#*$SEP}
        db_url=${db_url%$SEP*}
        DFLT_SCHEMA="--defaultSchemaName=$db_schema"

        echo "db.schema   = $db_schema"
fi

echo "db.url      = $db_url"
echo "changelog   = $CHANGELOG_FILE"

liquibase ()
{
   CMD="$LIQUIBASE_HOME/liquibase --driver=$DRIVER --classpath=$JDBC_CP --changeLogFile=$CHANGELOG_FILE $DFLT_SCHEMA --url=$db_url --username=$db_username --password=$db_password --logLevel=$LOG_LEVEL $COMMAND"
   #echo "$CMD"
   $CMD
}

if [ $# = 3 ]; then
  while true; do
    read -p "Do you wish to $COMMAND database [yes/no] ?" RESP
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
fi

