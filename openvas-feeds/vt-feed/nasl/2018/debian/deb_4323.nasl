# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704323");
  script_tag(name:"creation_date", value:"2018-10-17 22:00:00 +0000 (Wed, 17 Oct 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-4323)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4323");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4323");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2018-006");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/drupal7");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal7' package(s) announced via the DSA-4323 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were found in Drupal, a fully-featured content management framework, which could result in arbitrary code execution or an open redirect. For additional information, please refer to the upstream advisory at [link moved to references]

For the stable distribution (stretch), this problem has been fixed in version 7.52-2+deb9u5.

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