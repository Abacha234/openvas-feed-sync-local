# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845315");
  script_cve_id("CVE-2022-1097", "CVE-2022-24713", "CVE-2022-28281", "CVE-2022-28282", "CVE-2022-28283", "CVE-2022-28284", "CVE-2022-28285", "CVE-2022-28286", "CVE-2022-28287", "CVE-2022-28288", "CVE-2022-28289");
  script_tag(name:"creation_date", value:"2022-04-08 01:00:37 +0000 (Fri, 08 Apr 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-17 22:29:00 +0000 (Thu, 17 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5370-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5370-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5370-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-5370-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Firefox. If a user were
tricked into opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, execute script
unexpectedly, obtain sensitive information, conduct spoofing attacks,
or execute arbitrary code. (CVE-2022-1097, CVE-2022-24713, CVE-2022-28281,
CVE-2022-28282, CVE-2022-28284, CVE-2022-28285, CVE-2022-28286,
CVE-2022-28288, CVE-2022-28289)

A security issue was discovered with the sourceMapURL feature of devtools.
An attacker could potentially exploit this to include local files that
should have been inaccessible. (CVE-2022-28283)

It was discovered that selecting text caused Firefox to crash in some
circumstances. An attacker could potentially exploit this to cause a
denial of service. (CVE-2022-28287)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
