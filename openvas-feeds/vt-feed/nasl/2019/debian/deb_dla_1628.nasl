# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891628");
  script_cve_id("CVE-2018-18873", "CVE-2018-19539", "CVE-2018-19540", "CVE-2018-19541", "CVE-2018-19542", "CVE-2018-20570", "CVE-2018-20584", "CVE-2018-20622");
  script_tag(name:"creation_date", value:"2019-01-02 23:00:00 +0000 (Wed, 02 Jan 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-29 21:15:00 +0000 (Fri, 29 Jan 2021)");

  script_name("Debian: Security Advisory (DLA-1628)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1628");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1628-2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jasper' package(s) announced via the DLA-1628 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The update of jasper issued as DLA-1628-1 caused a regression due to the fix for CVE-2018-19542, a NULL pointer dereference in the function jp2_decode, which could lead to a denial-of-service. In some cases not only invalid jp2 files but also valid jp2 files were rejected.

For Debian 8 Jessie, this problem has been fixed in version 1.900.1-debian1-2.4+deb8u6.

We recommend that you upgrade your jasper packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'jasper' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);