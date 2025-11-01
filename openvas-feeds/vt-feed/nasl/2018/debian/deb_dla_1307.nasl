# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891307");
  script_cve_id("CVE-2018-0202", "CVE-2018-1000085");
  script_tag(name:"creation_date", value:"2018-03-26 22:00:00 +0000 (Mon, 26 Mar 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-20 18:30:00 +0000 (Wed, 20 Mar 2019)");

  script_name("Debian: Security Advisory (DLA-1307)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1307");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1307");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'clamav' package(s) announced via the DLA-1307 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Some vulnerabilities have been found in ClamAV, an open source antivirus engine:

CVE-2018-0202

It was found that ClamAV didn't process certain PDF files correctly, relating to a heap overflow. Specially crafted PDFs could yield ClamAV to crash, resulting in a denial-of-service or potentially execution of arbitrary code.

CVE-2018-1000085

Hanno Bock discovered that ClamAV didn't process XAR files correctly. Malformed XAR files could cause ClamAV to crash by an out of bounds heap read. This could result in a denial-of-service.

For Debian 7 Wheezy, these problems have been fixed in version 0.99.4+dfsg-1+deb7u1.

We recommend that you upgrade your clamav packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'clamav' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);