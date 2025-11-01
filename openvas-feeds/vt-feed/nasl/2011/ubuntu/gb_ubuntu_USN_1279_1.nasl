# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840821");
  script_cve_id("CVE-2011-2183", "CVE-2011-2491", "CVE-2011-2494", "CVE-2011-2495", "CVE-2011-2517", "CVE-2011-2905", "CVE-2011-2909");
  script_tag(name:"creation_date", value:"2011-11-25 06:33:33 +0000 (Fri, 25 Nov 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1279-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1279-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1279-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-backport-natty' package(s) announced via the USN-1279-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andrea Righi discovered a race condition in the KSM memory merging support.
If KSM was being used, a local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2011-2183)

Vasily Averin discovered that the NFS Lock Manager (NLM) incorrectly
handled unlock requests. A local attacker could exploit this to cause a
denial of service. (CVE-2011-2491)

Vasiliy Kulikov discovered that taskstats did not enforce access
restrictions. A local attacker could exploit this to read certain
information, leading to a loss of privacy. (CVE-2011-2494)

Vasiliy Kulikov discovered that /proc/PID/io did not enforce access
restrictions. A local attacker could exploit this to read certain
information, leading to a loss of privacy. (CVE-2011-2495)

It was discovered that the wireless stack incorrectly verified SSID
lengths. A local attacker could exploit this to cause a denial of service
or gain root privileges. (CVE-2011-2517)

Christian Ohm discovered that the perf command looks for configuration
files in the current directory. If a privileged user were tricked into
running perf in a directory containing a malicious configuration file, an
attacker could run arbitrary commands and possibly gain privileges.
(CVE-2011-2905)

Vasiliy Kulikov discovered that the Comedi driver did not correctly clear
memory. A local attacker could exploit this to read kernel stack memory,
leading to a loss of privacy. (CVE-2011-2909)");

  script_tag(name:"affected", value:"'linux-lts-backport-natty' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
