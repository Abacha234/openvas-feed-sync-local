# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703484");
  script_cve_id("CVE-2014-9765");
  script_tag(name:"creation_date", value:"2016-02-18 23:00:00 +0000 (Thu, 18 Feb 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-3484)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3484");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3484");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xdelta3' package(s) announced via the DSA-3484 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stepan Golosunov discovered that xdelta3, a diff utility which works with binary files, is affected by a buffer overflow vulnerability within the main_get_appheader function, which may lead to the execution of arbitrary code.

For the oldstable distribution (wheezy), this problem has been fixed in version 3.0.0.dfsg-1+deb7u1.

For the stable distribution (jessie), this problem has been fixed in version 3.0.8-dfsg-1+deb8u1.

For the testing distribution (stretch), this problem has been fixed in version 3.0.8-dfsg-1.1.

For the unstable distribution (sid), this problem has been fixed in version 3.0.8-dfsg-1.1.

We recommend that you upgrade your xdelta3 packages.");

  script_tag(name:"affected", value:"'xdelta3' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);