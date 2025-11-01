# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703290");
  script_cve_id("CVE-2015-1805", "CVE-2015-3636", "CVE-2015-4167");
  script_tag(name:"creation_date", value:"2015-06-17 22:00:00 +0000 (Wed, 17 Jun 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3290)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3290");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3290");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3290 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service, information leaks or data corruption.

CVE-2015-1805

Red Hat discovered that the pipe iovec read and write implementations may iterate over the iovec twice but will modify the iovec such that the second iteration accesses the wrong memory. A local user could use this flaw to crash the system or possibly for privilege escalation. This may also result in data corruption and information leaks in pipes between non-malicious processes.

CVE-2015-3636

Wen Xu and wushi of KeenTeam discovered that users allowed to create ping sockets can use them to crash the system and, on 32-bit architectures, for privilege escalation. However, by default, no users on a Debian system have access to ping sockets.

CVE-2015-4167

Carl Henrik Lunde discovered that the UDF implementation is missing a necessary length checks. A local user that can mount devices could use this flaw to crash the system.

For the oldstable distribution (wheezy), these problems have been fixed in version 3.2.68-1+deb7u2.

For the stable distribution (jessie), these problems were fixed in version 3.16.7-ckt11-1 or earlier, except for CVE-2015-4167 which will be fixed later.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);