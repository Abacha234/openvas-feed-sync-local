# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840267");
  script_cve_id("CVE-2007-6694", "CVE-2008-1375", "CVE-2008-1669", "CVE-2008-1675");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-614-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-614-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-614-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-backports-modules-2.6.24, linux-restricted-modules-2.6.24, linux-ubuntu-modules-2.6.24' package(s) announced via the USN-614-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PowerPC kernels did not correctly handle reporting
certain system details. By requesting a specific set of information,
a local attacker could cause a system crash resulting in a denial
of service. (CVE-2007-6694)

A race condition was discovered between dnotify fcntl() and close() in
the kernel. If a local attacker performed malicious dnotify requests,
they could cause memory consumption leading to a denial of service,
or possibly send arbitrary signals to any process. (CVE-2008-1375)

On SMP systems, a race condition existed in fcntl(). Local attackers
could perform malicious locks, causing system crashes and leading to
a denial of service. (CVE-2008-1669)

The tehuti network driver did not correctly handle certain IO functions.
A local attacker could perform malicious requests to the driver,
potentially accessing kernel memory, leading to privilege escalation
or access to private system information. (CVE-2008-1675)");

  script_tag(name:"affected", value:"'linux, linux-backports-modules-2.6.24, linux-restricted-modules-2.6.24, linux-ubuntu-modules-2.6.24' package(s) on Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
