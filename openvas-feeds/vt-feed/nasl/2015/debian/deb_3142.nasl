# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703142");
  script_cve_id("CVE-2012-6656", "CVE-2014-6040", "CVE-2014-7817", "CVE-2015-0235");
  script_tag(name:"creation_date", value:"2015-01-26 23:00:00 +0000 (Mon, 26 Jan 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3142)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3142");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3142");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'eglibc' package(s) announced via the DSA-3142 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been fixed in eglibc, Debian's version of the GNU C library:

CVE-2015-0235

Qualys discovered that the gethostbyname and gethostbyname2 functions were subject to a buffer overflow if provided with a crafted IP address argument. This could be used by an attacker to execute arbitrary code in processes which called the affected functions.

The original glibc bug was reported by Peter Klotz.

CVE-2014-7817

Tim Waugh of Red Hat discovered that the WRDE_NOCMD option of the wordexp function did not suppress command execution in all cases. This allows a context-dependent attacker to execute shell commands.

CVE-2012-6656

CVE-2014-6040

The charset conversion code for certain IBM multi-byte code pages could perform an out-of-bounds array access, causing the process to crash. In some scenarios, this allows a remote attacker to cause a persistent denial of service.

For the stable distribution (wheezy), these problems have been fixed in version 2.13-38+deb7u7.

For the upcoming stable distribution (jessie) and the unstable distribution (sid), the CVE-2015-0235 issue has been fixed in version 2.18-1 of the glibc package.

We recommend that you upgrade your eglibc packages.");

  script_tag(name:"affected", value:"'eglibc' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);