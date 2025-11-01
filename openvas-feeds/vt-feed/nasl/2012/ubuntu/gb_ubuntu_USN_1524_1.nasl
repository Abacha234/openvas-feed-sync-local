# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841100");
  script_cve_id("CVE-2011-3046", "CVE-2011-3050", "CVE-2011-3067", "CVE-2011-3068", "CVE-2011-3069", "CVE-2011-3071", "CVE-2011-3073", "CVE-2011-3074", "CVE-2011-3075", "CVE-2011-3078", "CVE-2012-0672", "CVE-2012-3615", "CVE-2012-3655", "CVE-2012-3656", "CVE-2012-3680");
  script_tag(name:"creation_date", value:"2012-08-09 04:51:55 +0000 (Thu, 09 Aug 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1524-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1524-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1524-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1027283");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit' package(s) announced via the USN-1524-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A large number of security issues were discovered in the WebKit browser and
JavaScript engines. If a user were tricked into viewing a malicious
website, a remote attacker could exploit a variety of issues related to web
browser security, including cross-site scripting attacks, denial of
service attacks, and arbitrary code execution.");

  script_tag(name:"affected", value:"'webkit' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
