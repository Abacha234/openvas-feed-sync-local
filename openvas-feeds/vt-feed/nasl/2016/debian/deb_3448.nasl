# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703448");
  script_cve_id("CVE-2013-4312", "CVE-2015-7566", "CVE-2015-8767", "CVE-2016-0723", "CVE-2016-0728");
  script_tag(name:"creation_date", value:"2016-01-18 23:00:00 +0000 (Mon, 18 Jan 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-17 21:40:00 +0000 (Tue, 17 Jan 2023)");

  script_name("Debian: Security Advisory (DSA-3448)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3448");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3448");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3448 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation or denial-of-service.

CVE-2013-4312

Tetsuo Handa discovered that it is possible for a process to open far more files than the process' limit leading to denial-of-service conditions.

CVE-2015-7566

Ralf Spenneberg of OpenSource Security reported that the visor driver crashes when a specially crafted USB device without bulk-out endpoint is detected.

CVE-2015-8767

An SCTP denial-of-service was discovered which can be triggered by a local attacker during a heartbeat timeout event after the 4-way handshake.

CVE-2016-0723

A use-after-free vulnerability was discovered in the TIOCGETD ioctl. A local attacker could use this flaw for denial-of-service.

CVE-2016-0728

The Perception Point research team discovered a use-after-free vulnerability in the keyring facility, possibly leading to local privilege escalation.

For the stable distribution (jessie), these problems have been fixed in version 3.16.7-ckt20-1+deb8u3.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);