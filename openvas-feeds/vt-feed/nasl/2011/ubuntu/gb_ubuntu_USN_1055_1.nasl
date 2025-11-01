# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840578");
  script_cve_id("CVE-2010-4351", "CVE-2011-0025");
  script_tag(name:"creation_date", value:"2011-02-04 13:19:53 +0000 (Fri, 04 Feb 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1055-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1055-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1055-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6, openjdk-6b18' package(s) announced via the USN-1055-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that IcedTea for Java did not properly verify
signatures when handling multiply signed or partially signed JAR files,
allowing an attacker to cause code to execute that appeared to come
from a verified source. (CVE-2011-0025)

USN 1052-1 fixed a vulnerability in OpenJDK for Ubuntu 9.10 and Ubuntu
10.04 LTS on all architectures, and Ubuntu 10.10 for all architectures
except for the armel (ARM) architecture. This update provides the
corresponding update for Ubuntu 10.10 on the armel (ARM) architecture.

Original advisory details:

 It was discovered that the JNLP SecurityManager in IcedTea for Java
 OpenJDK in some instances failed to properly apply the intended
 scurity policy in its checkPermission method. This could allow
 an attacker to execute code with privileges that should have been
 prevented. (CVE-2010-4351)");

  script_tag(name:"affected", value:"'openjdk-6, openjdk-6b18' package(s) on Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
