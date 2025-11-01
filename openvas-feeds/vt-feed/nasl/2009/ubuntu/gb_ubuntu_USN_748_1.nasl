# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63748");
  script_cve_id("CVE-2006-2426", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1100", "CVE-2009-1101", "CVE-2009-1102");
  script_tag(name:"creation_date", value:"2009-04-06 18:58:11 +0000 (Mon, 06 Apr 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-748-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-748-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-748-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6' package(s) announced via the USN-748-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that font creation could leak temporary files.
If a user were tricked into loading a malicious program or applet,
a remote attacker could consume disk space, leading to a denial of
service. (CVE-2006-2426, CVE-2009-1100)

It was discovered that the lightweight HttpServer did not correctly close
files on dataless connections. A remote attacker could send specially
crafted requests, leading to a denial of service. (CVE-2009-1101)

The Java Runtime Environment did not correctly validate certain generated
code. If a user were tricked into running a malicious applet a remote
attacker could execute arbitrary code. (CVE-2009-1102)

It was discovered that LDAP connections did not close correctly.
A remote attacker could send specially crafted requests, leading to a
denial of service. (CVE-2009-1093)

Java LDAP routines did not unserialize certain data correctly. A remote
attacker could send specially crafted requests that could lead to
arbitrary code execution. (CVE-2009-1094)

Java did not correctly check certain JAR headers. If a user or
automated system were tricked into processing a malicious JAR file,
a remote attacker could crash the application, leading to a denial of
service. (CVE-2009-1095, CVE-2009-1096)

It was discovered that PNG and GIF decoding in Java could lead to memory
corruption. If a user or automated system were tricked into processing
a specially crafted image, a remote attacker could crash the application,
leading to a denial of service. (CVE-2009-1097, CVE-2009-1098)");

  script_tag(name:"affected", value:"'openjdk-6' package(s) on Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
