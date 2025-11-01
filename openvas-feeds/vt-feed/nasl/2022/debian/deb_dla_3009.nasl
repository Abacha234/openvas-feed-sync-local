# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893009");
  script_cve_id("CVE-2022-27239", "CVE-2022-29869");
  script_tag(name:"creation_date", value:"2022-05-17 01:00:09 +0000 (Tue, 17 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-06 18:49:00 +0000 (Fri, 06 May 2022)");

  script_name("Debian: Security Advisory (DLA-3009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3009");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3009");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/cifs-utils");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cifs-utils' package(s) announced via the DLA-3009 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A couple of vulnerabilities were found in src:cifs-utils, a Common Internet File System utilities, and are as follows:

CVE-2022-27239

In cifs-utils, a stack-based buffer overflow when parsing the mount.cifs ip= command-line argument could lead to local attackers gaining root privileges.

CVE-2022-29869

cifs-utils, with verbose logging, can cause an information leak when a file contains = (equal sign) characters but is not a valid credentials file.

For Debian 9 stretch, these problems have been fixed in version 2:6.7-1+deb9u1.

We recommend that you upgrade your cifs-utils packages.

For the detailed security status of cifs-utils please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'cifs-utils' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);