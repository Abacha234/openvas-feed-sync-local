# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843118");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-5029", "CVE-2017-5030", "CVE-2017-5031", "CVE-2017-5033", "CVE-2017-5035", "CVE-2017-5037", "CVE-2017-5040", "CVE-2017-5041", "CVE-2017-5044", "CVE-2017-5045", "CVE-2017-5046");
  script_tag(name:"creation_date", value:"2017-03-30 04:32:20 +0000 (Thu, 30 Mar 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-22 20:38:00 +0000 (Fri, 22 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-3236-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3236-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3236-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt' package(s) announced via the USN-3236-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to obtain sensitive information, spoof
application UI by causing the security status API or webview URL to
indicate the wrong values, bypass security restrictions, cause a denial
of service via application crash, or execute arbitrary code.
(CVE-2017-5029, CVE-2017-5030, CVE-2017-5031, CVE-2017-5033,
CVE-2017-5035, CVE-2017-5037, CVE-2017-5040, CVE-2017-5041, CVE-2017-5044,
CVE-2017-5045, CVE-2017-5046)");

  script_tag(name:"affected", value:"'oxide-qt' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
