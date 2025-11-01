# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704693");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-11022", "CVE-2020-11023", "CVE-2020-13662");
  script_tag(name:"creation_date", value:"2020-05-28 03:00:10 +0000 (Thu, 28 May 2020)");
  script_version("2025-01-31T15:39:24+0000");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-13 20:31:00 +0000 (Thu, 13 May 2021)");

  script_name("Debian: Security Advisory (DSA-4693)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4693");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4693");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/drupal7");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal7' package(s) announced via the DSA-4693 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Drupal, a fully-featured content management framework, which could result in an open redirect or cross-site scripting.

For the oldstable distribution (stretch), these problems have been fixed in version 7.52-2+deb9u10.

We recommend that you upgrade your drupal7 packages.

For the detailed security status of drupal7 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'drupal7' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
