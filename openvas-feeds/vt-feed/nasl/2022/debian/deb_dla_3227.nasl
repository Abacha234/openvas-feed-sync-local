# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893227");
  script_cve_id("CVE-2022-32209");
  script_tag(name:"creation_date", value:"2022-12-07 02:00:50 +0000 (Wed, 07 Dec 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-06 12:40:00 +0000 (Wed, 06 Jul 2022)");

  script_name("Debian: Security Advisory (DLA-3227)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3227");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3227");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ruby-rails-html-sanitizer");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-rails-html-sanitizer' package(s) announced via the DLA-3227 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A potential cross-site scripting (XSS) vulnerability was discovered in ruby-rails-html-sanitizer, a library to clean (or sanitize) HTML for rendering within Ruby on Rails web applications.

For Debian 10 buster, this problem has been fixed in version 1.0.4-1+deb10u1.

We recommend that you upgrade your ruby-rails-html-sanitizer packages.

For the detailed security status of ruby-rails-html-sanitizer please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby-rails-html-sanitizer' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);