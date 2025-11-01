# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705032");
  script_cve_id("CVE-2019-15142", "CVE-2019-15143", "CVE-2019-15144", "CVE-2019-15145", "CVE-2019-18804", "CVE-2021-32490", "CVE-2021-32491", "CVE-2021-32492", "CVE-2021-32493", "CVE-2021-3500", "CVE-2021-3630");
  script_tag(name:"creation_date", value:"2021-12-29 02:00:32 +0000 (Wed, 29 Dec 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-08 11:15:00 +0000 (Thu, 08 Jul 2021)");

  script_name("Debian: Security Advisory (DSA-5032)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5032");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-5032");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/djvulibre");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'djvulibre' package(s) announced via the DSA-5032 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in djvulibre, a library and set of tools to handle documents in the DjVu format. An attacker could crash document viewers and possibly execute arbitrary code through crafted DjVu files.

For the oldstable distribution (buster), these problems have been fixed in version 3.5.27.1-10+deb10u1.

For the stable distribution (bullseye), these problems have been fixed in version 3.5.28-2.

We recommend that you upgrade your djvulibre packages.

For the detailed security status of djvulibre please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'djvulibre' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);