# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705270");
  script_cve_id("CVE-2022-40284");
  script_tag(name:"creation_date", value:"2022-11-05 02:00:03 +0000 (Sat, 05 Nov 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-08 17:12:00 +0000 (Tue, 08 Nov 2022)");

  script_name("Debian: Security Advisory (DSA-5270)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5270");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5270");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ntfs-3g");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ntfs-3g' package(s) announced via the DSA-5270 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yuchen Zeng and Eduardo Vela discovered a buffer overflow in NTFS-3G, a read-write NTFS driver for FUSE, due to incorrect validation of some of the NTFS metadata. A local user can take advantage of this flaw for local root privilege escalation.

For the stable distribution (bullseye), this problem has been fixed in version 1:2017.3.23AR.3-4+deb11u3.

We recommend that you upgrade your ntfs-3g packages.

For the detailed security status of ntfs-3g please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'ntfs-3g' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);