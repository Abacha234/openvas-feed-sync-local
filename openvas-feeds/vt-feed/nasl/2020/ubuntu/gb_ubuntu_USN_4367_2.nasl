# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844451");
  script_cve_id("CVE-2019-19377", "CVE-2020-11565", "CVE-2020-12657");
  script_tag(name:"creation_date", value:"2020-05-29 03:00:39 +0000 (Fri, 29 May 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4367-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4367-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4367-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1879690");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta, linux-signed' package(s) announced via the USN-4367-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4367-1 fixed vulnerabilities in the 5.4 Linux kernel. Unfortunately,
that update introduced a regression in overlayfs. This update corrects
the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that the btrfs implementation in the Linux kernel did not
 properly detect that a block was marked dirty in some situations. An
 attacker could use this to specially craft a file system image that, when
 unmounted, could cause a denial of service (system crash). (CVE-2019-19377)

 It was discovered that the linux kernel did not properly validate certain
 mount options to the tmpfs virtual memory file system. A local attacker
 with the ability to specify mount options could use this to cause a denial
 of service (system crash). (CVE-2020-11565)

 It was discovered that the block layer in the Linux kernel contained a race
 condition leading to a use-after-free vulnerability. A local attacker could
 possibly use this to cause a denial of service (system crash) or execute
 arbitrary code. (CVE-2020-12657)");

  script_tag(name:"affected", value:"'linux, linux-meta, linux-signed' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
