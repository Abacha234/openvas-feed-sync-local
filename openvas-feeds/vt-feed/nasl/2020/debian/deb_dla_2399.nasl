# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892399");
  script_cve_id("CVE-2020-16121", "CVE-2020-16122");
  script_tag(name:"creation_date", value:"2020-10-08 03:00:16 +0000 (Thu, 08 Oct 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-14 20:55:00 +0000 (Wed, 14 Apr 2021)");

  script_name("Debian: Security Advisory (DLA-2399)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2399");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2399");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/packagekit");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'packagekit' package(s) announced via the DLA-2399 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in packagekit, a package management service.

CVE-2020-16121

Vaisha Bernard discovered that PackageKit incorrectly handled certain methods. A local attacker could use this issue to learn the MIME type of any file on the system.

CVE-2020-16122

Sami Niemimaki discovered that PackageKit incorrectly handled local deb packages. A local user could possibly use this issue to install untrusted packages, contrary to expectations.

For Debian 9 stretch, these problems have been fixed in version 1.1.5-2+deb9u2.

We recommend that you upgrade your packagekit packages.

For the detailed security status of packagekit please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'packagekit' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);