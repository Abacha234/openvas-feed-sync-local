# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61639");
  script_cve_id("CVE-2006-5051", "CVE-2008-4109");
  script_tag(name:"creation_date", value:"2008-09-24 15:42:31 +0000 (Wed, 24 Sep 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1638)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1638");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1638");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssh' package(s) announced via the DSA-1638 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It has been discovered that the signal handler implementing the login timeout in Debian's version of the OpenSSH server uses functions which are not async-signal-safe, leading to a denial of service vulnerability (CVE-2008-4109).

The problem was originally corrected in OpenSSH 4.4p1 (CVE-2006-5051), but the patch backported to the version released with etch was incorrect.

Systems affected by this issue suffer from lots of zombie sshd processes. Processes stuck with a '[net]' process title have also been observed. Over time, a sufficient number of processes may accumulate such that further login attempts are impossible. Presence of these processes does not indicate active exploitation of this vulnerability. It is possible to trigger this denial of service condition by accident.

For the stable distribution (etch), this problem has been fixed in version 4.3p2-9etch3.

For the unstable distribution (sid) and the testing distribution (lenny), this problem has been fixed in version 4.6p1-1.

We recommend that you upgrade your openssh packages.");

  script_tag(name:"affected", value:"'openssh' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);