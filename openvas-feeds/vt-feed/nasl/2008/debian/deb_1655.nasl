# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61777");
  script_cve_id("CVE-2008-1514", "CVE-2008-3525", "CVE-2008-3831", "CVE-2008-4113", "CVE-2008-4445");
  script_tag(name:"creation_date", value:"2008-11-01 00:55:10 +0000 (Sat, 01 Nov 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1655)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1655");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1655");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6.24' package(s) announced via the DSA-1655 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service, privilege escalation or a leak of sensitive data. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-1514

Jan Kratochvil reported a local denial of service vulnerability in the ptrace interface for the s390 architecture. Local users can trigger an invalid pointer dereference, leading to a system panic.

CVE-2008-3525

Eugene Teo reported a lack of capability checks in the kernel driver for Granch SBNI12 leased line adapters (sbni), allowing local users to perform privileged operations.

CVE-2008-3831

Olaf Kirch discovered an issue with the i915 driver that may allow local users to cause memory corruption by use of an ioctl with insufficient privilege restrictions.

CVE-2008-4113/CVE-2008-4445 Eugene Teo discovered two issues in the SCTP subsystem which allow local users to obtain access to sensitive memory when the SCTP-AUTH extension is enabled.

For the stable distribution (etch), these problems have been fixed in version 2.6.24-6~etchnhalf.6.

We recommend that you upgrade your linux-2.6.24 packages.");

  script_tag(name:"affected", value:"'linux-2.6.24' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);