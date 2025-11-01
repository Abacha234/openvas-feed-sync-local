# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704923");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-1788", "CVE-2021-1844", "CVE-2021-1871", "CVE-2021-30682");
  script_tag(name:"creation_date", value:"2021-05-31 03:00:08 +0000 (Mon, 31 May 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-31 00:15:00 +0000 (Mon, 31 May 2021)");

  script_name("Debian: Security Advisory (DSA-4923)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4923");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4923");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/webkit2gtk");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'webkit2gtk' package(s) announced via the DSA-4923 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been discovered in the webkit2gtk web engine:

CVE-2021-1788

Francisco Alonso discovered that processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2021-1844

Clement Lecigne and Alison Huffman discovered that processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2021-1871

An anonymous researcher discovered that a remote attacker may be able to cause arbitrary code execution.

For the stable distribution (buster), these problems have been fixed in version 2.32.1-1~deb10u1.

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