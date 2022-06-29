#!/bin/sh

# https://stackoverflow.com/questions/65092032/maven-build-failed-but-exit-code-is-still-0

cd californium-extended
echo "*** Building and running Californium JUnit tests***"
mvn clean install | tee mvn_res
if grep 'BUILD FAILURE' mvn_res;then exit 1; fi;
if grep 'BUILD SUCCESS' mvn_res;then exit 0; else exit 1; fi;
rm mvn_res
cd ..

