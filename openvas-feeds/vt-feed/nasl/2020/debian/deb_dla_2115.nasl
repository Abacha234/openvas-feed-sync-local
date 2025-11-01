# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892115");
  script_cve_id("CVE-2020-9273");
  script_tag(name:"creation_date", value:"2020-02-22 04:00:07 +0000 (Sat, 22 Feb 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-21 23:15:00 +0000 (Fri, 21 Feb 2020)");

  script_name("Debian: Security Advisory (DLA-2115)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2115");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2115-2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'proftpd-dfsg' package(s) announced via the DLA-2115 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a regression in a previous fix for a use-after-free vulnerability in the proftpd-dfsg FTP server.

Exploitation of the original vulnerability within the memory pool handling could have allowed a remote attacker to execute arbitrary code on the affected system. However, the fix that was released in proftpd-dfsg version 1.3.5e+r1.3.5-2+deb8u6 had a regression around the handling of log formatting.

CVE-2020-9273

In ProFTPD 1.3.7, it is possible to corrupt the memory pool by interrupting the data transfer channel. This triggers a use-after-free in alloc_pool in pool.c, and possible remote code execution.

For Debian 8 Jessie, these problems have been fixed in version 1.3.5e+r1.3.5-2+deb8u7.

We recommend that you upgrade your proftpd-dfsg packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'proftpd-dfsg' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);