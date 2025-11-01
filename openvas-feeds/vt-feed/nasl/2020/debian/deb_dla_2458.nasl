# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892458");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-13666", "CVE-2020-13671");
  script_tag(name:"creation_date", value:"2020-11-20 04:00:30 +0000 (Fri, 20 Nov 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-15 04:15:00 +0000 (Tue, 15 Dec 2020)");

  script_name("Debian: Security Advisory (DLA-2458)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2458");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2458");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2020-007");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2020-012");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/drupal7");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal7' package(s) announced via the DLA-2458 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in Drupal, a fully-featured content management framework.

CVE-2020-13666

The Drupal AJAX API did not disable JSONP by default, which could lead to cross-site scripting.

For setups that relied on Drupal's AJAX API for JSONP requests, either JSONP will need to be re-enabled, or the jQuery AJAX API will have to be used instead.

See the upstream advisory for more details: [link moved to references]

CVE-2020-13671

Drupal failed to sanitize filenames on uploaded files, which could lead to those files being served as the wrong MIME type, or being executed depending on the server configuration.

It is also recommended to check previously uploaded files for malicious extensions. For more details see the upstream advisory: [link moved to references]

For Debian 9 stretch, these problems have been fixed in version 7.52-2+deb9u12.

We recommend that you upgrade your drupal7 packages.

For the detailed security status of drupal7 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'drupal7' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);