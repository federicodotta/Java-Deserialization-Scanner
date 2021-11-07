# Java Deserialization Scanner
Java Deserialization Scanner is a Burp Suite plugin aimed at detect and exploit Java deserialization vulnerabilities. It was written by Federico Dotta, Principal Security Analyst at HN Security.

The plugin is made up of three different components:

1.	Integration with Burp Suite active and passive scanner
2.	Manual tester, for the detection of Java deserialization vulnerabilities on custom insertion points
3.	Exploiter, that allow to actively exploit Java deserialization vulnerabilies, using frohoff ysoserial (https://github.com/frohoff/ysoserial)

# Author
- Federico Dotta, Principal Security Analyst at HN Security

# Contributors
- Jeremy Goldstein
- Andras Veres-Szentkiralyi

# Mini walkthrough (24/05/17)
A brief article containing a mini walkthrough on how to use the various components of the plugin can be found at the following URL:
https://web.archive.org/web/20201130104913/https://techblog.mediaservice.net/2017/05/reliable-discovery-and-exploitation-of-java-deserialization-vulnerabilities/

# Integration with Burp Suite active and passive scanner
Java Deserialization Scanner uses custom payloads generated with a modified version of "ysoserial", tool created by frohoff and gebl, to detect Java deserialization vulnerabilities. The original tool (https://github.com/frohoff/ysoserial) generate payloads for the execution of commands on the system, using the Runtime.exec function. Usually, however, it is not possible to see the output of the command and consequently it is not simple to write a scanner based on this kind of function. For this reason, a modified version of ysoserial is used to generate different types of payloads, usefull for the detection of the issue instead of the exploitation:

1. Payloads that execute a syncronous sleep function, in order to verify the presence of the issue depending on the time of the response
2. Payloads that execute a DNS resolution, in order to verify the presence of the issue using the Burp Suite Collaborator integrated in Burp Suite

Currently, the passive checks of the Java Deserialiation Scanner reported the presence of serialized Java objects in the HTTP requests and the active checks actively scan for the presence of weak deserialization functions in conjuction with the presence of the following weak libraries:

1.	Apache Commons Collections 3 (up to 3.2.1), with five different chains
2.	Apache Commons Collections 4 (up to 4.4.0), with two different chains
3.	Spring (up to 4.2.2), with two different chains
4.  Java 6 and Java 7 (up to Jdk7u21) without any weak library
5.	Hibernate 5
6.	JSON
7.	Rome
8.	Java 8 (up to Jdk8u20) without any weak library
9.	Apache Commons BeanUtils
10.	Javassist/Weld
11.	JBoss Interceptors
12.	Mozilla Rhino (two different chains)
13.	Vaadin

Furthermore, **URLSNDS payload has been introduced** to actively **detect Java deserialization without any vulnerable libraris**. If the plugin find only the URLDNS issue (and no vulnerable libraries), the attacker probably can execute DoS attacks but to achieve Remote Code Execution it is necessary more effort. Refer to [this link](https://web.archive.org/web/20210312114921/https://techblog.mediaservice.net/2020/04/java-deserialization-scanner-0-6-is-out/) for more details.

All the components of the plugin supports the following encodings:

1.	Raw
2.	Base64
3.	Ascii Hex
4.	GZIP
5.	Base64 GZIP

In the test folder there are some simple Java server applications that can be used to test the plugin. Every application employ a different vulnerable Java library.

# Manual tester
The plugin offer a dedicated tab to launch the detection with the sleep and DNS payloads on custom insertion points, in order to check the Java deserialization vulnerabilities in particular situations in which strange entry points do not allow the detection with the scanner. The results of the manual tester can be inserted between Burp Suite scanner results.

The manual tester offers an extra detection method: CPU detection. The CPU detection method is based on Wouter Coekaerts’ SerialDOS work (https://gist.github.com/coekie/a27cc406fc9f3dc7a70d) and it is able to detect deserialization issues without the presence of any vulnerable library, using an object that employs many CPU cycles for the deserialization task and checking the time of the response. The CPU detection method is not included by default in the active scan checks, because it must be used with caution: sending a huge number of “light” SerialDOS payloads may still cause problems on old or highly-loaded systems. 

# Exploiter
After that a Java deserialization vulnerability has been found, it is possible to actively exploit the issue with the Exploiting dedicated tab. The “Exploiting” tab offers a comfortable interface to exploit deserialization vulnerabilities. This tab uses the ysoserial tool to generate exploitation vectors and includes the generated payload in a HTTP request. ysoserial takes as argument a vulnerable library and a command and generates a serialized object in binary form that can be sent to the vulnerable application to execute the command on the target system (obviously if the target application is vulnerable). The Exploiting tab supports the same encoding formats as the detection sections of the plugin.

# Screenshot
![alt tag](https://raw.githubusercontent.com/federicodotta/Java-Deserialization-Scanner/master/JavaDeserializationScanner.png)

# Installation 
1.	Download Burp Suite: http://portswigger.net/burp/download.html
2.	Install Java Deserialization Scanner from the BApp Store or follow these steps:
3.	Download the last release of Java Deserialization Scanner
4.	Open Burp -> Extender -> Extensions -> Add -> Choose JavaDeserializationScannerXX.jar file

# User Guide
1.	After installation, the Java Deserialization Scanner active and passive checks will be added to the Burp Suite scanner (it is possible to disable the checks in the options tab)
2.	Simply run the active or passive scanner in order to check also for weak Java deserialization
3.  With the dedicated tab "Manual testing" it is possible to set the injection point and executing the attack with all the payloads
4.	With the dedicated tab "Exploiting" it is possibile to actively exploit Java deserialization vulnerabilites
5.	The "Configuration" contains all the needed configuration for the correct working of the plugin

# Improving Java Deserialization Scanner
In order to improve this extension, please report any issue founded in the plugin. Furthermore if you want report me any disclosed Java library usefull for the exploitation of this weakness and, if I have the time, I will add an active check for it in my plugin.

# Disclaimer
This software has been created purely for the purposes of academic research and for the development of effective defensive techniques, and is not intended to be used to attack systems except where explicitly authorized. Project maintainers are not responsible or liable for misuse of the software. Use responsibly.

# MIT License
Copyright (c) 2020 Java Deserialization Scanner

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:  

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.  

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.