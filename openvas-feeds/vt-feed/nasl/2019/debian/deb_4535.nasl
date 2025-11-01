# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704535");
  script_cve_id("CVE-2019-5094");
  script_tag(name:"creation_date", value:"2019-09-28 02:00:08 +0000 (Sat, 28 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-11 19:21:00 +0000 (Mon, 11 Jan 2021)");

  script_name("Debian: Security Advisory (DSA-4535)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4535");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4535");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/e2fsprogs");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'e2fsprogs' package(s) announced via the DSA-4535 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lilith of Cisco Talos discovered a buffer overflow flaw in the quota code used by e2fsck from the ext2/ext3/ext4 file system utilities. Running e2fsck on a malformed file system can result in the execution of arbitrary code.

For the oldstable distribution (stretch), this problem has been fixed in version 1.43.4-2+deb9u1.

For the stable distribution (buster), this problem has been fixed in version 1.44.5-1+deb10u2.

We recommend that you upgrade your e2fsprogs packages.

For the detailed security status of e2fsprogs please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'e2fsprogs' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);