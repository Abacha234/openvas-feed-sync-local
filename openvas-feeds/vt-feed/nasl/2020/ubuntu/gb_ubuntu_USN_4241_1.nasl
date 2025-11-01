# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844296");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-11745", "CVE-2019-17005", "CVE-2019-17008", "CVE-2019-17010", "CVE-2019-17011", "CVE-2019-17012", "CVE-2019-17016", "CVE-2019-17017", "CVE-2019-17022", "CVE-2019-17024", "CVE-2019-17026");
  script_tag(name:"creation_date", value:"2020-01-17 04:00:22 +0000 (Fri, 17 Jan 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-13 18:15:00 +0000 (Thu, 13 May 2021)");

  script_name("Ubuntu: Security Advisory (USN-4241-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4241-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4241-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-4241-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Thunderbird. If a user were
tricked in to opening a specially crafted website in a browsing context,
an attacker could potentially exploit these to cause a denial of service,
conduct cross-site scripting (XSS) attacks, or execute arbitrary code.
(CVE-2019-17005, CVE-2019-17008, CVE-2019-17010, CVE-2019-17011,
CVE-2019-17012, CVE-2019-17016, CVE-2019-17017, CVE-2019-17022,
CVE-2019-17024, CVE-2019-17026)

It was discovered that NSS incorrectly handled certain memory operations.
A remote attacker could potentially exploit this to cause a denial of
service, or execute arbitrary code. (CVE-2019-11745)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
