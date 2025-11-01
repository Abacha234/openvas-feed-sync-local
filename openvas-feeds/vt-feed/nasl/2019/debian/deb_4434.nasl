# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704434");
  script_cve_id("CVE-2019-11358");
  script_tag(name:"creation_date", value:"2019-04-21 02:00:05 +0000 (Sun, 21 Apr 2019)");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Debian: Security Advisory (DSA-4434)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4434");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4434");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2019-006");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/drupal7");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal7' package(s) announced via the DSA-4434 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A cross-site scripting vulnerability has been found in Drupal, a fully-featured content management framework. For additional information, please refer to the upstream advisory at [link moved to references].

For the stable distribution (stretch), this problem has been fixed in version 7.52-2+deb9u8.

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