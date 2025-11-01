# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841132");
  script_cve_id("CVE-2012-0044", "CVE-2012-2372", "CVE-2012-3400");
  script_tag(name:"creation_date", value:"2012-09-07 05:56:33 +0000 (Fri, 07 Sep 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-29 15:27:00 +0000 (Wed, 29 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-1555-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1555-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1555-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1555-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chen Haogang discovered an integer overflow that could result in memory
corruption. A local unprivileged user could use this to crash the system.
(CVE-2012-0044)

A flaw was found in the Linux kernel's Reliable Datagram Sockets (RDS)
protocol implementation. A local, unprivileged user could use this flaw to
cause a denial of service. (CVE-2012-2372)

Some errors where discovered in the Linux kernel's UDF file system, which
is used to mount some CD-ROMs and DVDs. An unprivileged local user could
use these flaws to crash the system. (CVE-2012-3400)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
