# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703929");
  script_cve_id("CVE-2017-2885");
  script_tag(name:"creation_date", value:"2017-08-09 22:00:00 +0000 (Wed, 09 Aug 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 17:25:00 +0000 (Tue, 07 Jun 2022)");

  script_name("Debian: Security Advisory (DSA-3929)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3929");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3929");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libsoup2.4' package(s) announced via the DSA-3929 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aleksandar Nikolic of Cisco Talos discovered a stack-based buffer overflow vulnerability in libsoup2.4, a HTTP library implementation in C. A remote attacker can take advantage of this flaw by sending a specially crafted HTTP request to cause an application using the libsoup2.4 library to crash (denial of service), or potentially execute arbitrary code.

For the oldstable distribution (jessie), this problem has been fixed in version 2.48.0-1+deb8u1.

For the stable distribution (stretch), this problem has been fixed in version 2.56.0-2+deb9u1.

We recommend that you upgrade your libsoup2.4 packages.");

  script_tag(name:"affected", value:"'libsoup2.4' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);