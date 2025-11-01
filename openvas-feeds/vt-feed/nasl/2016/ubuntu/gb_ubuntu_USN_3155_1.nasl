# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842991");
  script_cve_id("CVE-2016-9080", "CVE-2016-9893", "CVE-2016-9894", "CVE-2016-9895", "CVE-2016-9896", "CVE-2016-9897", "CVE-2016-9898", "CVE-2016-9899", "CVE-2016-9900", "CVE-2016-9901", "CVE-2016-9902", "CVE-2016-9903", "CVE-2016-9904");
  script_tag(name:"creation_date", value:"2016-12-14 04:53:54 +0000 (Wed, 14 Dec 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 13:43:00 +0000 (Wed, 01 Aug 2018)");

  script_name("Ubuntu: Security Advisory (USN-3155-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3155-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3155-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-3155-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities were discovered in Firefox. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit these to conduct cross-site scripting (XSS) attacks,
obtain sensitive information, cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-9080, CVE-2016-9893,
CVE-2016-9894, CVE-2016-9895, CVE-2016-9896, CVE-2016-9897, CVE-2016-9898,
CVE-2016-9899, CVE-2016-9900, CVE-2016-9901, CVE-2016-9902, CVE-2016-9903,
CVE-2016-9904)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
