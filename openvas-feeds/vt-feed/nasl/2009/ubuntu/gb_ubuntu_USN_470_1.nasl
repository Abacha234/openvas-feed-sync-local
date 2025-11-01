# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840165");
  script_cve_id("CVE-2007-1353", "CVE-2007-2451", "CVE-2007-2453");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-470-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-470-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-470-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/117314");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/UsingUUID");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-source-2.6.20' package(s) announced via the USN-470-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-464-1 fixed several vulnerabilities in the Linux kernel. Some
additional code changes were accidentally included in the Feisty update
which caused trouble for some people who were not using UUID-based
filesystem mounts. These changes have been reverted. We apologize for
the inconvenience. For more information see:
 [link moved to references]
 [link moved to references]

Ilja van Sprundel discovered that Bluetooth setsockopt calls could leak
kernel memory contents via an uninitialized stack buffer. A local
attacker could exploit this flaw to view sensitive kernel information.
(CVE-2007-1353)

The GEODE-AES driver did not correctly initialize its encryption key.
Any data encrypted using this type of device would be easily compromised.
(CVE-2007-2451)

The random number generator was hashing a subset of the available
entropy, leading to slightly less random numbers. Additionally, systems
without an entropy source would be seeded with the same inputs at boot
time, leading to a repeatable series of random numbers. (CVE-2007-2453)");

  script_tag(name:"affected", value:"'linux-source-2.6.20' package(s) on Ubuntu 7.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
