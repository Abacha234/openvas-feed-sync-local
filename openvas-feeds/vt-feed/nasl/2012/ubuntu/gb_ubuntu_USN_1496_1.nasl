# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841068");
  script_cve_id("CVE-2011-2685", "CVE-2011-2713", "CVE-2012-1149", "CVE-2012-2334");
  script_tag(name:"creation_date", value:"2012-07-03 04:56:04 +0000 (Tue, 03 Jul 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1496-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1496-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1496-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openoffice.org' package(s) announced via the USN-1496-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A stack-based buffer overflow was discovered in the Lotus Word Pro import
filter in OpenOffice.org. The default compiler options for affected
releases should reduce the vulnerability to a denial of service.
(CVE-2011-2685)

Huzaifa Sidhpurwala discovered that OpenOffice.org could be made to crash
if it opened a specially crafted Word document. (CVE-2011-2713)

Integer overflows were discovered in the graphics loading code of several
different image types. If a user were tricked into opening a specially
crafted file, an attacker could cause OpenOffice.org to crash or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2012-1149)

Sven Jacobi discovered an integer overflow when processing Escher graphics
records. If a user were tricked into opening a specially crafted PowerPoint
file, an attacker could cause OpenOffice.org to crash or possibly execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2012-2334)");

  script_tag(name:"affected", value:"'openoffice.org' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
