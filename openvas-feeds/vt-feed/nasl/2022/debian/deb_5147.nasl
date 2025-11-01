# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705147");
  script_cve_id("CVE-2022-1664");
  script_tag(name:"creation_date", value:"2022-05-26 01:00:14 +0000 (Thu, 26 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 18:18:00 +0000 (Tue, 07 Jun 2022)");

  script_name("Debian: Security Advisory (DSA-5147)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5147");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5147");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/dpkg");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dpkg' package(s) announced via the DSA-5147 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Max Justicz reported a directory traversal vulnerability in Dpkg::Source::Archive in dpkg, the Debian package management system. This affects extracting untrusted source packages in the v2 and v3 source package formats that include a debian.tar.

For the oldstable distribution (buster), this problem has been fixed in version 1.19.8.

For the stable distribution (bullseye), this problem has been fixed in version 1.20.10.

We recommend that you upgrade your dpkg packages.

For the detailed security status of dpkg please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'dpkg' package(s) on Debian 10, Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);