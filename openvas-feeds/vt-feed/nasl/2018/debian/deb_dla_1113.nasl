# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891113");
  script_cve_id("CVE-2017-0898", "CVE-2017-10784");
  script_tag(name:"creation_date", value:"2018-02-06 23:00:00 +0000 (Tue, 06 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-31 10:29:00 +0000 (Wed, 31 Oct 2018)");

  script_name("Debian: Security Advisory (DLA-1113)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1113");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-1113");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby1.8' package(s) announced via the DLA-1113 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Some vulnerabilities were found in the Ruby 1.8 package that affects the LTS distribution.

CVE-2017-0898

Buffer underrun vulnerability in Kernel.sprintf

CVE-2017-10784

Escape sequence injection vulnerability in the Basic authentication of WEBrick

For Debian 7 Wheezy, these problems have been fixed in version 1.8.7.358-7.1+deb7u4.

We recommend that you upgrade your ruby1.8 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby1.8' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);