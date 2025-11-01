# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57384");
  script_cve_id("CVE-2006-4005", "CVE-2006-4006");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1180)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1180");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1180");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bomberclone' package(s) announced via the DSA-1180 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Luigi Auriemma discovered two security related bugs in bomberclone, a free Bomberman clone. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-4005

The program copies remotely provided data unchecked which could lead to a denial of service via an application crash.

CVE-2006-4006

Bomberclone uses remotely provided data as length argument which can lead to the disclosure of private information.

For the stable distribution (sarge) these problems have been fixed in version 0.11.5-1sarge2.

For the unstable distribution (sid) these problems have been fixed in version 0.11.7-0.1.

We recommend that you upgrade your bomberclone package.");

  script_tag(name:"affected", value:"'bomberclone' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);