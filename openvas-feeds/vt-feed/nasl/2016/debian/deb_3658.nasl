# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703658");
  script_cve_id("CVE-2015-8948", "CVE-2016-6261", "CVE-2016-6263");
  script_tag(name:"creation_date", value:"2016-09-07 04:38:39 +0000 (Wed, 07 Sep 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)");

  script_name("Debian: Security Advisory (DSA-3658)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3658");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3658");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libidn' package(s) announced via the DSA-3658 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hanno Boeck discovered multiple vulnerabilities in libidn, the GNU library for Internationalized Domain Names (IDNs), allowing a remote attacker to cause a denial of service against an application using the libidn library (application crash).

For the stable distribution (jessie), these problems have been fixed in version 1.29-1+deb8u2.

For the testing distribution (stretch), these problems have been fixed in version 1.33-1.

For the unstable distribution (sid), these problems have been fixed in version 1.33-1.

We recommend that you upgrade your libidn packages.");

  script_tag(name:"affected", value:"'libidn' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);