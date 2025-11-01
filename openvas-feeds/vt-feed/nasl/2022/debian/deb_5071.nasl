# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705071");
  script_cve_id("CVE-2021-44142");
  script_tag(name:"creation_date", value:"2022-02-12 02:00:08 +0000 (Sat, 12 Feb 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-23 15:47:00 +0000 (Wed, 23 Feb 2022)");

  script_name("Debian: Security Advisory (DSA-5071)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5071");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5071");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/samba");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'samba' package(s) announced via the DSA-5071 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Samba, a SMB/CIFS file, print, and login server for Unix.

CVE-2021-44142

Orange Tsai reported an out-of-bounds heap write vulnerability in the VFS module vfs_fruit, which could result in remote execution of arbitrary code as root.

CVE-2022-0336

Kees van Vloten reported that Samba AD users with permission to write to an account can impersonate arbitrary services.

For the oldstable distribution (buster), these problems have been fixed in version 2:4.9.5+dfsg-5+deb10u3. As per DSA 5015-1, CVE-2022-0336 has not been addressed for the oldstable distribution (buster).

For the stable distribution (bullseye), these problems have been fixed in version 2:4.13.13+dfsg-1~deb11u3. Additionally, some followup fixes for CVE-2020-25717 are included in this update (Cf. #1001068).

We recommend that you upgrade your samba packages.

For the detailed security status of samba please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'samba' package(s) on Debian 10, Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);