# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844914");
  script_cve_id("CVE-2021-23994", "CVE-2021-23995", "CVE-2021-23996", "CVE-2021-23997", "CVE-2021-23998", "CVE-2021-23999", "CVE-2021-24000", "CVE-2021-24001", "CVE-2021-24002", "CVE-2021-29945", "CVE-2021-29946", "CVE-2021-29947");
  script_tag(name:"creation_date", value:"2021-04-27 03:00:29 +0000 (Tue, 27 Apr 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-25 20:07:00 +0000 (Fri, 25 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4926-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4926-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4926-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-4926-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Firefox. If a user were
tricked into opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, spoof the
browser UI, bypass security restrictions, trick the user into disclosing
confidential information, or execute arbitrary code. (CVE-2021-23994,
CVE-2021-23996, CVE-2021-23997, CVE-2021-23998, CVE-2021-23999,
CVE-2021-24000, CVE-2021-24001, CVE-2021-29945, CVE-2021-29946,
CVE-2021-29947)

A use-after-free was discovered when Responsive Design Mode was
enabled. If a user were tricked into opening a specially crafted
website with Responsive Design Mode enabled, an attacker could
potentially exploit this to cause a denial of service, or execute
arbitrary code. (CVE-2021-23995)

It was discovered that Firefox mishandled ftp URLs with encoded newline
characters. If a user were tricked into clicking on a specially crafted
link, an attacker could potentially exploit this to send arbitrary
FTP commands. (CVE-2021-24002)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
