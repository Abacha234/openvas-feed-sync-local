# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891862");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-10639", "CVE-2019-13272", "CVE-2019-2101");
  script_tag(name:"creation_date", value:"2019-07-24 02:00:09 +0000 (Wed, 24 Jul 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 15:42:00 +0000 (Wed, 02 Jun 2021)");

  script_name("Debian: Security Advisory (DLA-1862)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1862");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1862");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-1862 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2019-2101

Andrey Konovalov discovered that the USB Video Class driver (uvcvideo) did not consistently handle a type field in device descriptors, which could result in a heap buffer overflow. This could be used for denial of service or possibly for privilege escalation.

CVE-2019-10639

Amit Klein and Benny Pinkas discovered that the generation of IP packet IDs used a weak hash function that incorporated a kernel virtual address. In Linux 3.16 this hash function is not used for IP IDs but is used for other purposes in the network stack. In custom kernel configurations that enable kASLR, this might weaken kASLR.

CVE-2019-13272

Jann Horn discovered that the ptrace subsystem in the Linux kernel mishandles the management of the credentials of a process that wants to create a ptrace relationship, allowing a local user to obtain root privileges under certain scenarios.

For Debian 8 Jessie, these problems have been fixed in version 3.16.70-1. This update also fixes a regression introduced by the original fix for CVE-2019-11478 (#930904), and includes other fixes from upstream stable updates.

We recommend that you upgrade your linux and linux-latest packages. You will need to use 'apt-get upgrade --with-new-pkgs' or apt upgrade as the binary package names have changed.

We recommend that you upgrade your linux packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);