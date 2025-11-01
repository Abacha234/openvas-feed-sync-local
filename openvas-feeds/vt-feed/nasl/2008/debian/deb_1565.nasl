# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60931");
  script_cve_id("CVE-2007-6694", "CVE-2008-0007", "CVE-2008-1294", "CVE-2008-1375");
  script_tag(name:"creation_date", value:"2008-05-12 17:53:28 +0000 (Mon, 12 May 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1565)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1565");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1565");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-1565 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-6694

Cyrill Gorcunov reported a NULL pointer dereference in code specific to the CHRP PowerPC platforms. Local users could exploit this issue to achieve a Denial of Service (DoS).

CVE-2008-0007

Nick Piggin of SuSE discovered a number of issues in subsystems which register a fault handler for memory mapped areas. This issue can be exploited by local users to achieve a Denial of Service (DoS) and possibly execute arbitrary code.

CVE-2008-1294

David Peer discovered that users could escape administrator imposed cpu time limitations (RLIMIT_CPU) by setting a limit of 0.

CVE-2008-1375

Alexander Viro discovered a race condition in the directory notification subsystem that allows local users to cause a Denial of Service (oops) and possibly result in an escalation of privileges.

For the stable distribution (etch), these problems have been fixed in version 2.6.18.dfsg.1-18etch3.

The unstable (sid) and testing distributions will be fixed soon.

We recommend that you upgrade your linux-2.6, fai-kernels, and user-mode-linux packages.");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);