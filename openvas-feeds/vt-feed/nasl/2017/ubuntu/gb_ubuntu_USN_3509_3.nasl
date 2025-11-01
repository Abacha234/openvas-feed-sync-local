# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843402");
  script_cve_id("CVE-2017-1000405", "CVE-2017-12193", "CVE-2017-16643", "CVE-2017-16939");
  script_tag(name:"creation_date", value:"2017-12-15 11:41:32 +0000 (Fri, 15 Dec 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3509-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3509-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3509-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1737033");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-raspi2' package(s) announced via the USN-3509-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3509-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04
LTS. Unfortunately, it also introduced a regression that prevented the
Ceph network filesystem from being used. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Mohamed Ghannam discovered that a use-after-free vulnerability existed in
 the Netlink subsystem (XFRM) in the Linux kernel. A local attacker could
 use this to cause a denial of service (system crash) or possibly execute
 arbitrary code. (CVE-2017-16939)

 It was discovered that the Linux kernel did not properly handle copy-on-
 write of transparent huge pages. A local attacker could use this to cause a
 denial of service (application crashes) or possibly gain administrative
 privileges. (CVE-2017-1000405)

 Fan Wu, Haoran Qiu, and Shixiong Zhao discovered that the associative array
 implementation in the Linux kernel sometimes did not properly handle adding
 a new entry. A local attacker could use this to cause a denial of service
 (system crash). (CVE-2017-12193)

 Andrey Konovalov discovered an out-of-bounds read in the GTCO digitizer USB
 driver for the Linux kernel. A physically proximate attacker could use this
 to cause a denial of service (system crash) or possibly execute arbitrary
 code. (CVE-2017-16643)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-raspi2' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
