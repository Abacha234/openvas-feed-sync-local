# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704556");
  script_cve_id("CVE-2019-18281");
  script_tag(name:"creation_date", value:"2019-11-02 03:00:07 +0000 (Sat, 02 Nov 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-18 20:15:00 +0000 (Tue, 18 Feb 2020)");

  script_name("Debian: Security Advisory (DSA-4556)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4556");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4556");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/qtbase-opensource-src");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qtbase-opensource-src' package(s) announced via the DSA-4556 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds memory access was discovered in the Qt library, which could result in denial of service through a text file containing many directional characters.

The oldstable distribution (stretch) is not affected.

For the stable distribution (buster), this problem has been fixed in version 5.11.3+dfsg1-1+deb10u1.

We recommend that you upgrade your qtbase-opensource-src packages.

For the detailed security status of qtbase-opensource-src please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'qtbase-opensource-src' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);