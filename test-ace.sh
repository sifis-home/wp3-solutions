#!/bin/sh

# Build Californium (if needed)
FILE=californium-group-oscore/cf-oscore/target/cf-oscore-3.1.0-SNAPSHOT.jar
if [ -f "$FILE" ]; then
    echo "$FILE exists."
else 
    echo "$FILE does not exist."
    cd californium-group-oscore
    mvn clean install -DskipTests
    cd ..
fi

# Copy library Jar files from Californium to ACE lib folder
mkdir ace/lib
cp californium-group-oscore/cf-oscore/target/cf-oscore-3.1.0-SNAPSHOT-sources.jar ace/lib
cp californium-group-oscore/cf-oscore/target/cf-oscore-3.1.0-SNAPSHOT.jar ace/lib

cp californium-group-oscore/californium-core/target/californium-core-3.1.0-SNAPSHOT.jar ace/lib
cp californium-group-oscore/californium-core/target/californium-core-3.1.0-SNAPSHOT-sources.jar ace/lib
cp californium-group-oscore/californium-core/target/californium-core-3.1.0-SNAPSHOT-tests.jar ace/lib

cp californium-group-oscore/scandium-core/target/scandium-3.1.0-SNAPSHOT-sources.jar ace/lib
cp californium-group-oscore/scandium-core/target/scandium-3.1.0-SNAPSHOT.jar ace/lib
cp californium-group-oscore/scandium-core/target/scandium-3.1.0-SNAPSHOT-tests.jar ace/lib

cp californium-group-oscore/element-connector/target/element-connector-3.1.0-SNAPSHOT-sources.jar ace/lib
cp californium-group-oscore/element-connector/target/element-connector-3.1.0-SNAPSHOT-tests.jar ace/lib
cp californium-group-oscore/element-connector/target/element-connector-3.1.0-SNAPSHOT.jar ace/lib

# Install Mysql server (seems to be already installed in Github test environment)
echo "mysql-server mysql-server/root_password password root" | sudo debconf-set-selections
echo "mysql-server mysql-server/root_password_again password root" | sudo debconf-set-selections
sudo apt-get -y install mysql-server
sudo systemctl start mysql.service
echo "root" > ace/db.pwd

# Run ACE JUnit tests
cd ace
mvn -X -e clean install | tee mvn_res
if grep 'BUILD FAILURE' mvn_res;then exit 1; fi;
rm mvn_res
cd ..

