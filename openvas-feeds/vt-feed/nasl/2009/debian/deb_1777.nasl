# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63886");
  script_tag(name:"creation_date", value:"2009-04-28 18:40:12 +0000 (Tue, 28 Apr 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1777)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1777");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1777");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'git-core' package(s) announced via the DSA-1777 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Peter Palfrader discovered that in the Git revision control system, on some architectures files under /usr/share/git-core/templates/ were owned by a non-root user. This allows a user with that uid on the local system to write to these files and possibly escalate their privileges.

This issue only affects the DEC Alpha and MIPS (big and little endian) architectures.

For the old stable distribution (etch), this problem has been fixed in version 1.4.4.4-4+etch2.

For the stable distribution (lenny), this problem has been fixed in version 1.5.6.5-3+lenny1.

For the unstable distribution (sid), this problem has been fixed in version 1.6.2.1-1.

We recommend that you upgrade your git-core package.");

  script_tag(name:"affected", value:"'git-core' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);