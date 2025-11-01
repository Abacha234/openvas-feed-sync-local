# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703807");
  script_cve_id("CVE-2017-6009", "CVE-2017-6010", "CVE-2017-6011");
  script_tag(name:"creation_date", value:"2017-03-11 23:00:00 +0000 (Sat, 11 Mar 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-12 19:43:00 +0000 (Tue, 12 Mar 2019)");

  script_name("Debian: Security Advisory (DSA-3807)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3807");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3807");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icoutils' package(s) announced via the DSA-3807 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the icotool and wrestool tools of Icoutils, a set of programs that deal with MS Windows icons and cursors, which may result in denial of service or the execution of arbitrary code if a malformed .ico or .exe file is processed.

For the stable distribution (jessie), these problems have been fixed in version 0.31.0-2+deb8u3.

For the upcoming stable distribution (stretch), these problems have been fixed in version 0.31.2-1.

For the unstable distribution (sid), these problems have been fixed in version 0.31.2-1.

We recommend that you upgrade your icoutils packages.");

  script_tag(name:"affected", value:"'icoutils' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);