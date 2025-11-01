# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703332");
  script_cve_id("CVE-2015-2213", "CVE-2015-5622", "CVE-2015-5730", "CVE-2015-5731", "CVE-2015-5732", "CVE-2015-5734");
  script_tag(name:"creation_date", value:"2015-08-10 22:00:00 +0000 (Mon, 10 Aug 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3332)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3332");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3332");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-3332 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been fixed in Wordpress, the popular blogging engine.

CVE-2015-2213

SQL Injection allowed a remote attacker to compromise the site.

CVE-2015-5622

The robustness of the shortcodes HTML tags filter has been improved. The parsing is a bit more strict, which may affect your installation. This is the corrected version of the patch that needed to be reverted in DSA 3328-2.

CVE-2015-5730

A potential timing side-channel attack in widgets.

CVE-2015-5731

An attacker could lock a post that was being edited.

CVE-2015-5732

Cross site scripting in a widget title allows an attacker to steal sensitive information.

CVE-2015-5734

Fix some broken links in the legacy theme preview.

The issues were discovered by Marc-Alexandre Montpas of Sucuri, Helen Hou-Sandi of the WordPress security team, Netanel Rubin of Check Point, Ivan Grigorov, Johannes Schmitt of Scrutinizer and Mohamed A. Baset.

For the stable distribution (jessie), these problems have been fixed in version 4.1+dfsg-1+deb8u4.

For the unstable distribution (sid), these problems have been fixed in version 4.2.4+dfsg-1.

We recommend that you upgrade your wordpress packages.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);