#--------------------------------------------------------------------------------------------#
# Tool     : Maven-based CVE fetcher                                                         #                       
# Author   : Areed Ahmed Arshad                                                              #                                                
# Function : This pulls maven data from maven repo based on the soup input and also fetches  #
#            the CVE for each                                                                #
# Date     : 08/02/2021                                                                      #                                                                          |
# Version  : 1.0                                                                             #                                                        |
#--------------------------------------------------------------------------------------------#

import os
import json
import httplib2

def title():
    print("|**************************************************************|")
    print("|Tool   : Maven-based CVE fetcher                              |")
    print("|Author : Areed Ahmed Arshad                                   |")
    print("|Date   : 08/02/2021                                           |")
    print("|Version: 1.0                                                  |")
    print("|Desc   : This pulls maven data from maven repo based on the   |")
    print("|          soup input and also fetches the CVE for each        |")
    print("|**************************************************************|\n")

def get_dep_xml(g_n, n, v):
    search_uri = '/solrsearch/select?q=g:%20{}%20%20AND%20a:%20{}%20%20AND%20v:%20{}%20&rows=20&wt=json'.format(g_n, n,v)
    conn = httplib2.HTTPConnectionWithTimeout('search.maven.org')
    conn.request('GET', search_uri)
    response = conn.getresponse()
    if response.status == 200:
        search_result = json.loads(response.read())
        if search_result['response']['numFound'] >= 1:
            count = search_result['response']['numFound']
            i = 0
            while i != count:
                project = search_result['response']['docs'][i]
                group_id = project.get('g')
                artifact_id = project.get('a')
                version_id = project.get('v')
                print(">> Fetching data from maven for: " + artifact_id + " from Group: " + group_id)
                f.write(
                    '<dependency>\n<groupId>{}</groupId>\n<artifactId>{}</artifactId>\n<version>{}</version>\n</dependency>\n'.format(
                        group_id, artifact_id, version_id))
                i = i + 1         

def extract(path):
    cve_file = open(path, 'rt')
    lines = cve_file.read().split('\n')
    cve_list = []
    for l in lines:
        if not l == "":
            cve_list.append(l)
    cve_file.close()
    return cve_list

def start():
    print(">> Maven Pom file creater plus CVE finder")
    print("-" * 50)
    print(">> Make sure the data is in format: artifact-id version-id in each line, eg: XmlSchema 1.4.2")
    soup = extract(input(">> Enter the path containing the soup.txt file: "))
    f.write(
        '<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd"><modelVersion>4.0.0</modelVersion><groupId>ICU_Vul_Checker</groupId><artifactId>ICU_Vul_Checker</artifactId><version>0.0.1-SNAPSHOT</version><name>ICU_Vul_Checker</name>')
    f.write(
        '<repositories><repository><id>mednet</id><name>mednet-mvn</name><url>http://uscasdartfctry:8081/artifactory/mednet-mvn/</url></repository></repositories><dependencies>')
    for i in range(len(soup)):
        group_name, aritfact_name, version = soup[i].split(":")
        get_dep_xml(group_name, aritfact_name, version)
    f.write(
        '<dependency><groupId>org.owasp</groupId><artifactId>dependency-check-maven</artifactId><version>6.0.5</version></dependency></dependencies></project>')
    f.close()
    print(">> Find the file pom.xml in your project root directory")
    cve_pom = input(">> Do you want to find CVE's based on the pom.xml file?Y or N: ")
    if cve_pom == 'Y' or cve_pom == 'y':
        print(
            ">> If the tool errors out then the pom.xml artifacts are missing in the maven repository present")
        print(
            ">> Please fix them and run the command \'mvn org.owasp:dependency-check-maven:check\' in your directory containing the pom.xml file")
        os.system("mvn org.owasp:dependency-check-maven:check")

if __name__ == '__main__':
    try:
        title()
        start()   
    except:
        pass