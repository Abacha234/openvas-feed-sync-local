# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840499");
  script_cve_id("CVE-2010-3081", "CVE-2010-3301");
  script_tag(name:"creation_date", value:"2010-09-22 06:32:53 +0000 (Wed, 22 Sep 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 14:05:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-988-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-988-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-988-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-source-2.6.15' package(s) announced via the USN-988-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ben Hawkes discovered that the Linux kernel did not correctly validate
memory ranges on 64bit kernels when allocating memory on behalf of 32bit
system calls. On a 64bit system, a local attacker could perform malicious
multicast getsockopt calls to gain root privileges. (CVE-2010-3081)

Ben Hawkes discovered that the Linux kernel did not correctly filter
registers on 64bit kernels when performing 32bit system calls. On a
64bit system, a local attacker could manipulate 32bit system calls to
gain root privileges. (Ubuntu 6.06 LTS and 8.04 LTS were not affected.)
(CVE-2010-3301)");

  script_tag(name:"affected", value:"'linux, linux-source-2.6.15' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
