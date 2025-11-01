# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66809");
  script_cve_id("CVE-2010-0292", "CVE-2010-0293", "CVE-2010-0294");
  script_tag(name:"creation_date", value:"2010-02-10 20:51:26 +0000 (Wed, 10 Feb 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1992)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1992");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-1992");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chrony' package(s) announced via the DSA-1992 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in chrony, a pair of programs which are used to maintain the accuracy of the system clock on a computer. These issues are similar to the NTP security flaw CVE-2009-3563. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-0292

chronyd replies to all cmdmon packets with NOHOSTACCESS messages even for unauthorized hosts. An attacker can abuse this behaviour to force two chronyd instances to play packet ping-pong by sending such a packet with spoofed source address and port. This results in high CPU and network usage and thus denial of service conditions.

CVE-2010-0293

The client logging facility of chronyd doesn't limit memory that is used to store client information. An attacker can cause chronyd to allocate large amounts of memory by sending NTP or cmdmon packets with spoofed source addresses resulting in memory exhaustion.

CVE-2010-0294

chronyd lacks of a rate limit control to the syslog facility when logging received packets from unauthorized hosts. This allows an attacker to cause denial of service conditions via filling up the logs and thus disk space by repeatedly sending invalid cmdmon packets.

For the oldstable distribution (etch), this problem has been fixed in version 1.21z-5+etch1.

For the stable distribution (lenny), this problem has been fixed in version 1.23-6+lenny1.

For the testing (squeeze) and unstable (sid) distribution, this problem will be fixed soon.

We recommend that you upgrade your chrony packages.");

  script_tag(name:"affected", value:"'chrony' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);