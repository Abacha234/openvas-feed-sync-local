# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704201");
  script_cve_id("CVE-2017-5715", "CVE-2018-10471", "CVE-2018-10472", "CVE-2018-10981", "CVE-2018-10982", "CVE-2018-8897");
  script_tag(name:"creation_date", value:"2018-05-14 22:00:00 +0000 (Mon, 14 May 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4201)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4201");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4201");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xen");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-4201 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor:

CVE-2018-8897

Andy Lutomirski and Nick Peterson discovered that incorrect handling of debug exceptions could result in privilege escalation.

CVE-2018-10471

An error was discovered in the mitigations against Meltdown which could result in denial of service.

CVE-2018-10472

Anthony Perard discovered that incorrect parsing of CDROM images can result in information disclosure.

CVE-2018-10981

Jan Beulich discovered that malformed device models could result in denial of service.

CVE-2018-10982

Roger Pau Monne discovered that incorrect handling of high precision event timers could result in denial of service and potentially privilege escalation.

For the stable distribution (stretch), these problems have been fixed in version 4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6.

We recommend that you upgrade your xen packages.

For the detailed security status of xen please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);