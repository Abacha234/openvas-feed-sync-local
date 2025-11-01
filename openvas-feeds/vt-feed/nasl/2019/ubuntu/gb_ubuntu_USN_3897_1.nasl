# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843914");
  script_cve_id("CVE-2016-5824", "CVE-2018-18356", "CVE-2018-18500", "CVE-2018-18501", "CVE-2018-18505", "CVE-2018-18509", "CVE-2019-5785");
  script_tag(name:"creation_date", value:"2019-02-27 03:14:42 +0000 (Wed, 27 Feb 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3897-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3897-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3897-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-3897-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free was discovered in libical. If a user were tricked in to
opening a specially crafted ICS calendar file, an attacker could
potentially exploit this to cause a denial of service. (CVE-2016-5824)

Multiple security issues were discovered in Thunderbird. If a user were
tricked in to opening a specially crafted message, an attacker could
potentially exploit these to cause a denial of service, or execute
arbitrary code. (CVE-2018-18356, CVE-2018-18500, CVE-2019-5785)

Multiple security issues were discovered in Thunderbird. If a user were
tricked in to opening a specially crafted website in a browsing context,
an attacker could potentially exploit these to cause a denial of service,
gain additional privileges by escaping the sandbox, or execute arbitrary
code. (CVE-2018-18501, CVE-2018-18505)

An issue was discovered with S/MIME signature verification in some
circumstances. An attacker could potentially exploit this by spoofing
signatures for arbitrary content. (CVE-2018-18509)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
