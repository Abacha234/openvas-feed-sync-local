# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844567");
  script_cve_id("CVE-2020-12400", "CVE-2020-12401", "CVE-2020-15664", "CVE-2020-15665", "CVE-2020-15666", "CVE-2020-15668", "CVE-2020-15670", "CVE-2020-6829");
  script_tag(name:"creation_date", value:"2020-09-04 03:00:21 +0000 (Fri, 04 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4474-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4474-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4474-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1893021");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-4474-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4474-1 fixed vulnerabilities in Firefox. The update introduced various
minor regressions. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked in to opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service, trick the user
 in to installing a malicious extension, spoof the URL bar, leak sensitive
 information between origins, or execute arbitrary code. (CVE-2020-15664,
 CVE-2020-15665, CVE-2020-15666, CVE-2020-15670)

 It was discovered that NSS incorrectly handled certain signatures.
 An attacker could possibly use this issue to expose sensitive information.
 (CVE-2020-12400, CVE-2020-12401, CVE-2020-6829)

 A data race was discovered when importing certificate information in to
 the trust store. An attacker could potentially exploit this to cause an
 unspecified impact. (CVE-2020-15668)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
