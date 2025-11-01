# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54324");
  script_cve_id("CVE-2005-0988", "CVE-2005-1228");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-752)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-752");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-752");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gzip' package(s) announced via the DSA-752 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two problems have been discovered in gzip, the GNU compression utility. The Common Vulnerabilities and Exposures project identifies the following problems.

CAN-2005-0988

Imran Ghory discovered a race condition in the permissions setting code in gzip. When decompressing a file in a directory an attacker has access to, gunzip could be tricked to set the file permissions to a different file the user has permissions to.

CAN-2005-1228

Ulf Harnhammar discovered a path traversal vulnerability in gunzip. When gunzip is used with the -N option an attacker could use this vulnerability to create files in an arbitrary directory with the permissions of the user.

For the oldstable distribution (woody) these problems have been fixed in version 1.3.2-3woody5.

For the stable distribution (sarge) these problems have been fixed in version 1.3.5-10.

For the unstable distribution (sid) these problems have been fixed in version 1.3.5-10.

We recommend that you upgrade your gzip package.");

  script_tag(name:"affected", value:"'gzip' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);