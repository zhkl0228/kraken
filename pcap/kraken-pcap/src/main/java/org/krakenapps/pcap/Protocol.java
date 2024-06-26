/*
 * Copyright 2010 NCHOVY
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.krakenapps.pcap;

public enum Protocol {

	FTP, HTTP, MSN, POP3, SMTP, SNMP, TELNET, SMB, NETBIOS, DHCP, SSH, WHOIS, DNS, SQLNET, TFTP, FINGER, NTP, IMAP, BGP, SYSLOG, MYSQL, POSTGRES, MSSQL,
	SSL, HTTP2,

	/**
	 * user defined 1
	 */
	USR_DEF1,

	/**
	 * user defined 2
	 */
	USR_DEF2,

	/**
	 * user defined 3
	 */
	USR_DEF3
}
