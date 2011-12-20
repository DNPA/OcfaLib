#! /bin/bash
export PGUSER=ocfa
if [ -z $1 ] 
    then echo usage: initstore.sh \<dbname\>
    exit -1
fi
createdb $1
cat $OCFAROOT/bin/storedb.sql | psql $1
#echo "update pg_database set datdba=(select usesysid from pg_user where usename='ocfa')where datname='$1';"|psql $1
