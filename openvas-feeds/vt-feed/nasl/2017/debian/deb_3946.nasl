# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703946");
  script_cve_id("CVE-2017-11423", "CVE-2017-6419");
  script_tag(name:"creation_date", value:"2017-08-17 22:00:00 +0000 (Thu, 17 Aug 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-21 10:29:00 +0000 (Sun, 21 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-3946)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3946");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3946");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libmspack' package(s) announced via the DSA-3946 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libsmpack, a library used to handle Microsoft compression formats, did not properly validate its input. A remote attacker could craft malicious CAB or CHM files and use this flaw to cause a denial of service via application crash, or potentially execute arbitrary code.

For the oldstable distribution (jessie), these problems have been fixed in version 0.5-1+deb8u1.

For the stable distribution (stretch), these problems have been fixed in version 0.5-1+deb9u1.

We recommend that you upgrade your libmspack packages.");

  script_tag(name:"affected", value:"'libmspack' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);