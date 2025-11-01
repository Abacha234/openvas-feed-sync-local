# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840872");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2011-3377", "CVE-2011-3389", "CVE-2011-3521", "CVE-2011-3544", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3553", "CVE-2011-3554");
  script_tag(name:"creation_date", value:"2012-01-25 05:45:29 +0000 (Wed, 25 Jan 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1263-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1263-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1263-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/891761");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6, openjdk-6b18' package(s) announced via the USN-1263-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1263-1 fixed vulnerabilities in OpenJDK 6. The upstream patch for
the chosen plaintext attack on the block-wise AES encryption algorithm
(CVE-2011-3389) introduced a regression that caused TLS/SSL connections
to fail when using certain algorithms. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Deepak Bhole discovered a flaw in the Same Origin Policy (SOP)
 implementation in the IcedTea web browser plugin. This could allow a
 remote attacker to open connections to certain hosts that should
 not be permitted. (CVE-2011-3377)

 Juliano Rizzo and Thai Duong discovered that the block-wise AES
 encryption algorithm block-wise as used in TLS/SSL was vulnerable to
 a chosen-plaintext attack. This could allow a remote attacker to view
 confidential data. (CVE-2011-3389)

 It was discovered that a type confusion flaw existed in the in
 the Internet Inter-Orb Protocol (IIOP) deserialization code. A
 remote attacker could use this to cause an untrusted application
 or applet to execute arbitrary code by deserializing malicious
 input. (CVE-2011-3521)

 It was discovered that the Java scripting engine did not perform
 SecurityManager checks. This could allow a remote attacker to cause
 an untrusted application or applet to execute arbitrary code with
 the full privileges of the JVM. (CVE-2011-3544)

 It was discovered that the InputStream class used a global buffer to
 store input bytes skipped. An attacker could possibly use this to gain
 access to sensitive information. (CVE-2011-3547)

 It was discovered that a vulnerability existed in the AWTKeyStroke
 class. A remote attacker could cause an untrusted application or applet
 to execute arbitrary code. (CVE-2011-3548)

 It was discovered that an integer overflow vulnerability existed
 in the TransformHelper class in the Java2D implementation. A remote
 attacker could use this cause a denial of service via an application
 or applet crash or possibly execute arbitrary code. (CVE-2011-3551)

 It was discovered that the default number of available UDP sockets for
 applications running under SecurityManager restrictions was set too
 high. A remote attacker could use this with a malicious application or
 applet exhaust the number of available UDP sockets to cause a denial
 of service for other applets or applications running within the same
 JVM. (CVE-2011-3552)

 It was discovered that Java API for XML Web Services (JAX-WS) could
 incorrectly expose a stack trace. A remote attacker could potentially
 use this to gain access to sensitive information. (CVE-2011-3553)

 It was discovered that the unpacker for pack200 JAR files did not
 sufficiently check for errors. An attacker could cause a denial of
 service or possibly execute arbitrary code through a specially crafted
 pack200 JAR file. (CVE-2011-3554)

 It was discovered that the RMI registration implementation did not
 properly ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'openjdk-6, openjdk-6b18' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
