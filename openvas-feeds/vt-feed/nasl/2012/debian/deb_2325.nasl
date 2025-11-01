# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70540");
  script_cve_id("CVE-2011-4062");
  script_tag(name:"creation_date", value:"2012-02-11 07:26:03 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2325)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2325");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2325");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kfreebsd-8' package(s) announced via the DSA-2325 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Buffer overflow in the Linux emulation support in FreeBSD kernel allows local users to cause a denial of service (panic) and possibly execute arbitrary code by calling the bind system call with a long path for a UNIX-domain socket, which is not properly handled when the address is used by other unspecified system calls.

For the stable distribution (squeeze), this problem has been fixed in version 8.1+dfsg-8+squeeze2.

For the unstable distribution (sid), this problem has been fixed in version 8.2-9.

We recommend that you upgrade your kfreebsd-8 packages.");

  script_tag(name:"affected", value:"'kfreebsd-8' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);