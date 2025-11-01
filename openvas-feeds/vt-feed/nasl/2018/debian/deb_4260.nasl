# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704260");
  script_cve_id("CVE-2018-14679", "CVE-2018-14680", "CVE-2018-14681", "CVE-2018-14682");
  script_tag(name:"creation_date", value:"2018-08-01 22:00:00 +0000 (Wed, 01 Aug 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-26 11:45:00 +0000 (Mon, 26 Apr 2021)");

  script_name("Debian: Security Advisory (DSA-4260)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4260");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4260");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libmspack");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libmspack' package(s) announced via the DSA-4260 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in libsmpack, a library used to handle Microsoft compression formats. A remote attacker could craft malicious CAB, CHM or KWAJ files and use these flaws to cause a denial of service via application crash, or potentially execute arbitrary code.

For the stable distribution (stretch), these problems have been fixed in version 0.5-1+deb9u2.

We recommend that you upgrade your libmspack packages.

For the detailed security status of libmspack please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libmspack' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);