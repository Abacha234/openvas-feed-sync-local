# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702632");
  script_cve_id("CVE-2013-0231", "CVE-2013-0871");
  script_tag(name:"creation_date", value:"2013-02-24 23:00:00 +0000 (Sun, 24 Feb 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2632)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2632");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2632");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-2632 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-0231

Jan Beulich provided a fix for an issue in the Xen PCI backend drivers. Users of guests on a system using passed-through PCI devices can create a denial of service of the host system due to the use of non-ratelimited kernel log messages.

CVE-2013-0871

Suleiman Souhlal and Salman Qazi of Google, with help from Aaron Durbin and Michael Davidson of Google, discovered an issue in the ptrace subsystem. Due to a race condition with PTRACE_SETREGS, local users can cause kernel stack corruption and execution of arbitrary code.

For the stable distribution (squeeze), this problem has been fixed in version 2.6.32-48squeeze1.

The following matrix lists additional source packages that were rebuilt for compatibility with or to take advantage of this update:



Debian 6.0 (squeeze)

user-mode-linux

2.6.32-1um-4+48squeeze1

We recommend that you upgrade your linux-2.6 and user-mode-linux packages.");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);