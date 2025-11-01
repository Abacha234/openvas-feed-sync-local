# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67030");
  script_cve_id("CVE-2010-0547", "CVE-2010-0787");
  script_tag(name:"creation_date", value:"2010-03-16 16:25:39 +0000 (Tue, 16 Mar 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2004)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2004");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2004");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'samba' package(s) announced via the DSA-2004 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two local vulnerabilities have been discovered in samba, a SMB/CIFS file, print, and login server for Unix. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-3297

Ronald Volgers discovered that a race condition in mount.cifs allows local users to mount remote filesystems over arbitrary mount points.

CVE-2010-0547

Jeff Layton discovered that missing input sanitising in mount.cifs allows denial of service by corrupting /etc/mtab.

For the stable distribution (lenny), these problems have been fixed in version 2:3.2.5-4lenny9.

For the unstable distribution (sid), these problems have been fixed in version 2:3.4.5~dfsg-2.

We recommend that you upgrade your samba packages.");

  script_tag(name:"affected", value:"'samba' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);