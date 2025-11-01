# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843122");
  script_cve_id("CVE-2017-5398", "CVE-2017-5399", "CVE-2017-5400", "CVE-2017-5401", "CVE-2017-5402", "CVE-2017-5403", "CVE-2017-5404", "CVE-2017-5405", "CVE-2017-5406", "CVE-2017-5407", "CVE-2017-5408", "CVE-2017-5410", "CVE-2017-5412", "CVE-2017-5413", "CVE-2017-5414", "CVE-2017-5415", "CVE-2017-5416", "CVE-2017-5417", "CVE-2017-5418", "CVE-2017-5419", "CVE-2017-5420", "CVE-2017-5421", "CVE-2017-5422", "CVE-2017-5426", "CVE-2017-5427");
  script_tag(name:"creation_date", value:"2017-03-31 04:35:49 +0000 (Fri, 31 Mar 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3216-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3216-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3216-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1671079");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-3216-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3216-1 fixed vulnerabilities in Firefox. The update resulted in a
startup crash when Firefox is used with XRDP. This update fixes the
problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked in to opening a specially crafted website, an attacker could
 potentially exploit these to bypass same origin restrictions, obtain
 sensitive information, spoof the addressbar, spoof the print dialog,
 cause a denial of service via application crash or hang, or execute
 arbitrary code. (CVE-2017-5398, CVE-2017-5399, CVE-2017-5400,
 CVE-2017-5401, CVE-2017-5402, CVE-2017-5403, CVE-2017-5404, CVE-2017-5405,
 CVE-2017-5406, CVE-2017-5407, CVE-2017-5408, CVE-2017-5410, CVE-2017-5412,
 CVE-2017-5413, CVE-2017-5414, CVE-2017-5415, CVE-2017-5416, CVE-2017-5417,
 CVE-2017-5418, CVE-2017-5419, CVE-2017-5420, CVE-2017-5421, CVE-2017-5422,
 CVE-2017-5426, CVE-2017-5427)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
