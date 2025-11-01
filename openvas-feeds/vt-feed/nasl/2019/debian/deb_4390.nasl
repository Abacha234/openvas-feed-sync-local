# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704390");
  script_cve_id("CVE-2019-8308");
  script_tag(name:"creation_date", value:"2019-02-11 23:00:00 +0000 (Mon, 11 Feb 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4390)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4390");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4390");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/flatpak");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'flatpak' package(s) announced via the DSA-4390 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Flatpak, an application deployment framework for desktop apps, insufficiently restricted the execution of apply_extra scripts which could potentially result in privilege escalation.

For the stable distribution (stretch), this problem has been fixed in version 0.8.9-0+deb9u2.

We recommend that you upgrade your flatpak packages.

For the detailed security status of flatpak please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'flatpak' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);