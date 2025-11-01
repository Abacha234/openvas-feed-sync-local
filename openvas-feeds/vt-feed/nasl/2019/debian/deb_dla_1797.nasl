# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891797");
  script_cve_id("CVE-2019-11358", "CVE-2019-11831");
  script_tag(name:"creation_date", value:"2019-05-21 02:00:26 +0000 (Tue, 21 May 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-29 16:29:00 +0000 (Wed, 29 Sep 2021)");

  script_name("Debian: Security Advisory (DLA-1797)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1797");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1797");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2019-006");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2019-007");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal7' package(s) announced via the DLA-1797 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in drupal7, a PHP web site platform. The vulnerabilities affect the embedded versions of the jQuery JavaScript library and the Typo3 Phar Stream Wrapper library.

CVE-2019-11358

It was discovered that the jQuery version embedded in Drupal was prone to a cross site scripting vulnerability in jQuery.extend().

For additional information, please refer to the upstream advisory at [link moved to references].

CVE-2019-11831

It was discovered that incomplete validation in a Phar processing library embedded in Drupal, a fully-featured content management framework, could result in information disclosure.

For additional information, please refer to the upstream advisory at [link moved to references].

For Debian 8 Jessie, these problems have been fixed in version 7.32-1+deb8u17.

We recommend that you upgrade your drupal7 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'drupal7' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);