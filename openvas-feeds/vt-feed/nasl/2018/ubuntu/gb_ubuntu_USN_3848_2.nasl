# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843858");
  script_cve_id("CVE-2017-18174", "CVE-2018-12896", "CVE-2018-18690", "CVE-2018-18710");
  script_tag(name:"creation_date", value:"2018-12-21 06:23:49 +0000 (Fri, 21 Dec 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-21 11:29:00 +0000 (Fri, 21 Dec 2018)");

  script_name("Ubuntu: Security Advisory (USN-3848-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3848-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3848-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws, linux-lts-xenial, linux-meta-aws, linux-meta-lts-xenial' package(s) announced via the USN-3848-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3848-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
14.04 LTS.

It was discovered that a double free existed in the AMD GPIO driver in the
Linux kernel. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2017-18174)

It was discovered that an integer overrun vulnerability existed in the
POSIX timers implementation in the Linux kernel. A local attacker could use
this to cause a denial of service. (CVE-2018-12896)

Kanda Motohiro discovered that writing extended attributes to an XFS file
system in the Linux kernel in certain situations could cause an error
condition to occur. A local attacker could use this to cause a denial of
service. (CVE-2018-18690)

It was discovered that an integer overflow vulnerability existed in the
CDROM driver of the Linux kernel. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2018-18710)");

  script_tag(name:"affected", value:"'linux-aws, linux-lts-xenial, linux-meta-aws, linux-meta-lts-xenial' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
