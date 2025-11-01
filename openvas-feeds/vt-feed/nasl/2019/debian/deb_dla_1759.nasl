# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891759");
  script_cve_id("CVE-2019-1787", "CVE-2019-1788", "CVE-2019-1789");
  script_tag(name:"creation_date", value:"2019-04-23 02:00:07 +0000 (Tue, 23 Apr 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-07 15:55:00 +0000 (Thu, 07 Nov 2019)");

  script_name("Debian: Security Advisory (DLA-1759)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1759");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1759");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'clamav' package(s) announced via the DLA-1759 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Out-of-bounds read and write conditions have been fixed in clamav.

CVE-2019-1787

An out-of-bounds heap read condition may occur when scanning PDF documents. The defect is a failure to correctly keep track of the number of bytes remaining in a buffer when indexing file data.

CVE-2019-1788

An out-of-bounds heap write condition may occur when scanning OLE2 files such as Microsoft Office 97-2003 documents. The invalid write happens when an invalid pointer is mistakenly used to initialize a 32bit integer to zero. This is likely to crash the application.

CVE-2019-1789

An out-of-bounds heap read condition may occur when scanning PE files (i.e. Windows EXE and DLL files) that have been packed using Aspack as a result of inadequate bound-checking.

For Debian 8 Jessie, these problems have been fixed in version 0.100.3+dfsg-0+deb8u1.

We recommend that you upgrade your clamav packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'clamav' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);