# Yara C-ICAP Server Module. 

This is a c-icap server (http://c-icap.sourceforge.net/) yara (http://code.google.com/p/yara-project/) module.

Brief FAQ:

-- What is Yara :-) " .. YARA is a tool aimed at helping malware researchers to identify and classify malware samples... "
-- What is C-icap server " .. c-icap is an implementation of an ICAP server. It can be used with HTTP proxies that support the ICAP protocol to implement content adaptation and filtering .."

-- Why you want yara module: if you're an ISP with transparent proxy server, you want to catch malware before your users do :)

## Installation:


1. [Download and build yara] (http://code.google.com/p/yara-project)
2. Download and build c-icap server
3. Download C-icap modules source tree. 
4. place this yara module into c-icap-modules
5. Include yara folder into Makefile.am of the root folder where the code is unpacked.
6. Build and install modules
include following configuration lines in c-icap server config file:

```
Service yara_match  srv_yara.so
ServiceAlias yara srv_yara
srv_yara.YARAPath  /usr/local/etc/yara_rules

```


