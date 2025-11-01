# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60372");
  script_cve_id("CVE-2008-0163", "CVE-2008-0600");
  script_tag(name:"creation_date", value:"2008-02-15 22:29:21 +0000 (Fri, 15 Feb 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1494)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1494");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1494");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-1494 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The vmsplice system call did not properly verify address arguments passed by user space processes, which allowed local attackers to overwrite arbitrary kernel memory, gaining root privileges (CVE-2008-0010, CVE-2008-0600).

In the vserver-enabled kernels, a missing access check on certain symlinks in /proc enabled local attackers to access resources in other vservers (CVE-2008-0163).

The old stable distribution (sarge) is not affected by this problem.

For the stable distribution (etch), this problem has been fixed in version 2.6.18.dfsg.1-18etch1.

In addition to these fixes, this update also incorporates changes from the upcoming point release of the stable distribution.

Some architecture builds were not yet available at the time of DSA-1494-1. This update to DSA-1494 provides linux-2.6 packages for these remaining architectures, as well as additional binary packages that are built from source code provided by linux-2.6.

The unstable (sid) and testing (lenny) distributions will be fixed soon.

We recommend that you upgrade your linux-2.6, fai-kernels, and user-mode-linux packages.");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);