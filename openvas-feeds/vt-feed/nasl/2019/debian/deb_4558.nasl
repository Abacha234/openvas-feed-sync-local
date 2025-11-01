# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704558");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-8625", "CVE-2019-8710", "CVE-2019-8720", "CVE-2019-8743", "CVE-2019-8764", "CVE-2019-8766", "CVE-2019-8769", "CVE-2019-8771", "CVE-2019-8782", "CVE-2019-8783", "CVE-2019-8808", "CVE-2019-8811", "CVE-2019-8813", "CVE-2019-8815", "CVE-2019-8816", "CVE-2019-8819", "CVE-2019-8820", "CVE-2019-8823", "CVE-2021-30666", "CVE-2021-30761");
  script_tag(name:"creation_date", value:"2019-11-06 03:00:08 +0000 (Wed, 06 Nov 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-14 19:20:00 +0000 (Tue, 14 Sep 2021)");

  script_name("Debian: Security Advisory (DSA-4558)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4558");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4558");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/webkit2gtk");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'webkit2gtk' package(s) announced via the DSA-4558 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the webkit2gtk web engine:

CVE-2019-8625

Sergei Glazunov discovered that maliciously crafted web content may lead to universal cross site scripting.

CVE-2019-8720

Wen Xu discovered that maliciously crafted web content may lead to arbitrary code execution.

CVE-2019-8769

Pierre Reimertz discovered that visiting a maliciously crafted website may reveal browsing history.

CVE-2019-8771

Eliya Stein discovered that maliciously crafted web content may violate iframe sandboxing policy.

For the stable distribution (buster), these problems have been fixed in version 2.26.1-3~deb10u1.

We recommend that you upgrade your webkit2gtk packages.

For the detailed security status of webkit2gtk please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'webkit2gtk' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);