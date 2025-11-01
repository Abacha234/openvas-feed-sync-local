# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705055");
  script_cve_id("CVE-2021-3995", "CVE-2021-3996");
  script_tag(name:"creation_date", value:"2022-01-26 02:00:36 +0000 (Wed, 26 Jan 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 18:13:00 +0000 (Mon, 29 Aug 2022)");

  script_name("Debian: Security Advisory (DSA-5055)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5055");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5055");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/util-linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'util-linux' package(s) announced via the DSA-5055 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Qualys Research Labs discovered two vulnerabilities in util-linux's libmount. These flaws allow an unprivileged user to unmount other users' filesystems that are either world-writable themselves or mounted in a world-writable directory ( CVE-2021-3996), or to unmount FUSE filesystems that belong to certain other users ( CVE-2021-3995).

For the stable distribution (bullseye), these problems have been fixed in version 2.36.1-8+deb11u1.

We recommend that you upgrade your util-linux packages.

For the detailed security status of util-linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'util-linux' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);