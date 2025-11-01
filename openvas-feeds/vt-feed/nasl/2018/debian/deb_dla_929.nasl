# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890929");
  script_cve_id("CVE-2015-8981", "CVE-2017-5852", "CVE-2017-5853", "CVE-2017-5886", "CVE-2017-6844", "CVE-2017-7379");
  script_tag(name:"creation_date", value:"2018-01-16 23:00:00 +0000 (Tue, 16 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-21 19:05:00 +0000 (Tue, 21 Mar 2017)");

  script_name("Debian: Security Advisory (DLA-929)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-929");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-929");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libpodofo' package(s) announced via the DLA-929 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several heap-based buffer overflows, integer overflows and NULL pointer dereferences have been discovered in libpodofo, a library for manipulating PDF files, that allow remote attackers to cause a denial of service (application crash) or other unspecified impact via a crafted PDF document.

For Debian 7 Wheezy, these problems have been fixed in version 0.9.0-1.1+deb7u1.

We recommend that you upgrade your libpodofo packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libpodofo' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);