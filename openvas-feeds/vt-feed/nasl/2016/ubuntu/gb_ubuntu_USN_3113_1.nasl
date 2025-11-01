# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842940");
  script_cve_id("CVE-2016-1586", "CVE-2016-5181", "CVE-2016-5182", "CVE-2016-5185", "CVE-2016-5186", "CVE-2016-5187", "CVE-2016-5188", "CVE-2016-5189", "CVE-2016-5192", "CVE-2016-5194");
  script_tag(name:"creation_date", value:"2016-11-08 10:22:43 +0000 (Tue, 08 Nov 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-21 13:04:00 +0000 (Thu, 21 Nov 2019)");

  script_name("Ubuntu: Security Advisory (USN-3113-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3113-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3113-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt' package(s) announced via the USN-3113-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a long running unload handler could cause an
incognito profile to be reused in some circumstances. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to obtain sensitive information. (CVE-2016-1586)

Multiple security vulnerabilities were discovered in Chromium. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit these to conduct cross-site scripting (XSS) attacks,
spoof an application's URL bar, obtain sensitive information, cause a
denial of service via application crash, or execute arbitrary code.
(CVE-2016-5181, CVE-2016-5182, CVE-2016-5185, CVE-2016-5186,
CVE-2016-5187, CVE-2016-5188, CVE-2016-5189, CVE-2016-5192, CVE-2016-5194)");

  script_tag(name:"affected", value:"'oxide-qt' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
