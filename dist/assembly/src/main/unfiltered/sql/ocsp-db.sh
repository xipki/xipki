#!/bin/sh

LIQUIBASE_HOME=liquibase

COMMAND=$1

PROP_FILE=ocsp-publisher.properties
CHANGELOG_FILE=ocsp-init.xml

JDBC_CP=$( echo ../lib/ext/*.jar | sed 's/ /:/g')

# retrieve the database configuration
cat ../ocsp-config/$PROP_FILE | sed 's/\./_/' > .$PROP_FILE
. ./.$PROP_FILE
rm .$PROP_FILE -f
echo db.driverClassName=$db_driverClassName
echo db.username=$db_username
#echo db.password=$db_password


DRIVER=$db_driverClassName

DFLT_SCHEMA=

if [ "$DRIVER" = "com.ibm.db2.jcc.DB2Driver" ]; then
        echo "Database type: DB2"
        SEP=":currentSchema="
        db_schema=${db_url#*$SEP}
        db_url=${db_url%$SEP*}
        DFLT_SCHEMA="--defaultSchemaName=$db_schema"

        echo db.schema=$db_schema
        echo db.url=$db_url
else
        echo "Database type: -"
        echo db.url=$db_url
fi

liquibase ()
{
   CMD="liquibase/liquibase --driver=$DRIVER --classpath=$JDBC_CP --changeLogFile=$CHANGELOG_FILE $DFLT_SCHEMA --url=$db_url --username=$db_username --password=$db_password $COMMAND"
   #echo "$CMD"
   $CMD
}

if [ $# == 1 ]; then
  while true; do
    read -p "Do you wish to $COMMAND database? y/n " RESP
    if [ "$RESP" = "y" ]; then
       liquibase
       break
    elif [ "$RESP" = "n" ]; then
       break
    else
       echo "Please answer with y or n"
    fi
  done
else
  echo 'Usage: '
  echo   'ocsp-db.sh <command>'
  echo  ''
  echo  'Command:'
  echo     migrate
  echo     update
  echo     dropAll
fi

