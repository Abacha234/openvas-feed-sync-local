# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843620");
  script_cve_id("CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5390", "CVE-2018-5391");
  script_tag(name:"creation_date", value:"2018-08-19 04:29:00 +0000 (Sun, 19 Aug 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3741-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3741-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3741-3");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1787258");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1787127");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta' package(s) announced via the USN-3741-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3741-1 introduced mitigations in the Linux kernel for Ubuntu 14.04
LTS to address L1 Terminal Fault (L1TF) vulnerabilities (CVE-2018-3620,
CVE-2018-3646). Unfortunately, the update introduced regressions
that caused kernel panics when booting in some environments as well
as preventing Java applications from starting. This update fixes
the problems.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that memory present in the L1 data cache of an Intel CPU
 core may be exposed to a malicious process that is executing on the CPU
 core. This vulnerability is also known as L1 Terminal Fault (L1TF). A local
 attacker in a guest virtual machine could use this to expose sensitive
 information (memory from other guests or the host OS). (CVE-2018-3646)

 It was discovered that memory present in the L1 data cache of an Intel CPU
 core may be exposed to a malicious process that is executing on the CPU
 core. This vulnerability is also known as L1 Terminal Fault (L1TF). A local
 attacker could use this to expose sensitive information (memory from the
 kernel or other processes). (CVE-2018-3620)

 Juha-Matti Tilli discovered that the TCP implementation in the Linux kernel
 performed algorithmically expensive operations in some situations when
 handling incoming packets. A remote attacker could use this to cause a
 denial of service. (CVE-2018-5390)

 Juha-Matti Tilli discovered that the IP implementation in the Linux kernel
 performed algorithmically expensive operations in some situations when
 handling incoming packet fragments. A remote attacker could use this to
 cause a denial of service. (CVE-2018-5391)");

  script_tag(name:"affected", value:"'linux, linux-meta' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
