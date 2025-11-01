# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843177");
  script_cve_id("CVE-2017-3509", "CVE-2017-3511", "CVE-2017-3526", "CVE-2017-3533", "CVE-2017-3539", "CVE-2017-3544");
  script_tag(name:"creation_date", value:"2017-05-19 05:10:00 +0000 (Fri, 19 May 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3275-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3275-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3275-3");
  script_xref(name:"URL", value:"https://www.ubuntu.com/usn/usn-3275-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1691126");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-7' package(s) announced via the USN-3275-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3275-2 fixed vulnerabilities in OpenJDK 7. Unfortunately, the
update introduced a regression when handling TLS handshakes. This
update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that OpenJDK improperly re-used cached NTLM
 connections in some situations. A remote attacker could possibly
 use this to cause a Java application to perform actions with the
 credentials of a different user. (CVE-2017-3509)

 It was discovered that an untrusted library search path flaw existed
 in the Java Cryptography Extension (JCE) component of OpenJDK. A
 local attacker could possibly use this to gain the privileges of a
 Java application. (CVE-2017-3511)

 It was discovered that the Java API for XML Processing (JAXP) component
 in OpenJDK did not properly enforce size limits when parsing XML
 documents. An attacker could use this to cause a denial of service
 (processor and memory consumption). (CVE-2017-3526)

 It was discovered that the FTP client implementation in OpenJDK did
 not properly sanitize user inputs. If a user was tricked into opening
 a specially crafted FTP URL, a remote attacker could use this to
 manipulate the FTP connection. (CVE-2017-3533)

 It was discovered that OpenJDK allowed MD5 to be used as an algorithm
 for JAR integrity verification. An attacker could possibly use this
 to modify the contents of a JAR file without detection. (CVE-2017-3539)

 It was discovered that the SMTP client implementation in OpenJDK
 did not properly sanitize sender and recipient addresses. A remote
 attacker could use this to specially craft email addresses and gain
 control of a Java application's SMTP connections. (CVE-2017-3544)");

  script_tag(name:"affected", value:"'openjdk-7' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
