# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703573");
  script_cve_id("CVE-2016-3710", "CVE-2016-3712");
  script_tag(name:"creation_date", value:"2016-05-08 22:00:00 +0000 (Sun, 08 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-14 15:43:00 +0000 (Thu, 14 May 2020)");

  script_name("Debian: Security Advisory (DSA-3573)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3573");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3573");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DSA-3573 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in qemu, a fast processor emulator.

CVE-2016-3710

Wei Xiao and Qinghao Tang of 360.cn Inc discovered an out-of-bounds read and write flaw in the QEMU VGA module. A privileged guest user could use this flaw to execute arbitrary code on the host with the privileges of the hosting QEMU process.

CVE-2016-3712

Zuozhi Fzz of Alibaba Inc discovered potential integer overflow or out-of-bounds read access issues in the QEMU VGA module. A privileged guest user could use this flaw to mount a denial of service (QEMU process crash).

For the stable distribution (jessie), these problems have been fixed in version 1:2.1+dfsg-12+deb8u6.

We recommend that you upgrade your qemu packages.");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);