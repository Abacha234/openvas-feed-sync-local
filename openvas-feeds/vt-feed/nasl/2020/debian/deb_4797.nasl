# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704797");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-13543", "CVE-2020-13584", "CVE-2020-9947", "CVE-2020-9948", "CVE-2020-9951", "CVE-2020-9983", "CVE-2021-1817", "CVE-2021-1820", "CVE-2021-1825", "CVE-2021-1826", "CVE-2021-30661");
  script_tag(name:"creation_date", value:"2020-11-26 04:00:10 +0000 (Thu, 26 Nov 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-17 14:31:00 +0000 (Fri, 17 Sep 2021)");

  script_name("Debian: Security Advisory (DSA-4797)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4797");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4797");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/webkit2gtk");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'webkit2gtk' package(s) announced via the DSA-4797 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been discovered in the webkit2gtk web engine:

CVE-2020-9948

Brendan Draper discovered that processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2020-9951

Marcin Noga discovered that processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2020-9983

zhunki discovered that processing maliciously crafted web content may lead to code execution.

CVE-2020-13584

Cisco discovered that processing maliciously crafted web content may lead to arbitrary code execution.

For the stable distribution (buster), these problems have been fixed in version 2.30.3-1~deb10u1.

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