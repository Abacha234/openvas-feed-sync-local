# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702729");
  script_cve_id("CVE-2013-4134", "CVE-2013-4135");
  script_tag(name:"creation_date", value:"2013-07-27 22:00:00 +0000 (Sat, 27 Jul 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2729)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2729");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2729");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openafs' package(s) announced via the DSA-2729 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenAFS, the implementation of the distributed filesystem AFS, has been updated to no longer use DES for the encryption of tickets. Additional migration steps are needed to fully set the update into effect. For more information please see the upstream advisory: OPENAFS-SA-2013-003

In addition the encrypt option to the vos tool was fixed.

For the oldstable distribution (squeeze), these problems have been fixed in version 1.4.12.1+dfsg-4+squeeze2.

For the stable distribution (wheezy), these problems have been fixed in version 1.6.1-3+deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 1.6.5-1.

We recommend that you upgrade your openafs packages.");

  script_tag(name:"affected", value:"'openafs' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);