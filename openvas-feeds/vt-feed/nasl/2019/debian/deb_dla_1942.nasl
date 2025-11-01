# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891942");
  script_cve_id("CVE-2019-13376", "CVE-2019-16993");
  script_tag(name:"creation_date", value:"2019-10-01 02:00:16 +0000 (Tue, 01 Oct 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-21 13:34:00 +0000 (Thu, 21 Nov 2019)");

  script_name("Debian: Security Advisory (DLA-1942)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1942");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1942-2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpbb3' package(s) announced via the DLA-1942 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a follow-up to DLA-1942-1.

There was some confusion about the correct fix for CVE-2019-13776.

The correct announcement for this DLA should have been:

Package : phpbb3 Version : 3.0.12-5+deb8u4 CVE ID : CVE-2019-13776 CVE-2019-16993

CVE-2019-16993

In phpBB, includes/acp/acp_bbcodes.php had improper verification of a CSRF token on the BBCode page in the Administration Control Panel. An actual CSRF attack was possible if an attacker also managed to retrieve the session id of a reauthenticated administrator prior to targeting them.

CVE-2019-13776

phpBB allowed the stealing of an Administration Control Panel session id by leveraging CSRF in the Remote Avatar feature. The CSRF Token Hijacking lead to stored XSS.

For Debian 8 Jessie, these problems have been fixed in version 3.0.12-5+deb8u4.

We recommend that you upgrade your phpbb3 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'phpbb3' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);