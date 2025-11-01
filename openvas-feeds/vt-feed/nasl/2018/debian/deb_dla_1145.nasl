# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891145");
  script_cve_id("CVE-2017-5595");
  script_tag(name:"creation_date", value:"2018-02-07 23:00:00 +0000 (Wed, 07 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-16 14:09:00 +0000 (Thu, 16 Feb 2017)");

  script_name("Debian: Security Advisory (DLA-1145)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1145");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-1145");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/source-package/zoneminder");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'zoneminder' package(s) announced via the DLA-1145 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in zoneminder. This update fixes only a serious file disclosure vulnerability (CVE-2017-5595).

The application has been found to suffer from many other problems such as SQL injection vulnerabilities, cross-site scripting issues, cross-site request forgery, session fixation vulnerability. Due to the amount of issues and to the relative invasiveness of the relevant patches, those issues will not be fixed in Wheezy. We thus advise you to restrict access to zoneminder to trusted users only. If you want to review the list of ignored issues, you can check the security tracker: [link moved to references]

We recommend that you upgrade your zoneminder packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]

For Debian 7 Wheezy, these issues have been fixed in zoneminder version 1.25.0-4+deb7u2");

  script_tag(name:"affected", value:"'zoneminder' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);