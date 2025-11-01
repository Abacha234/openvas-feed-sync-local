# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53404");
  script_cve_id("CVE-2002-0391");
  script_tag(name:"creation_date", value:"2008-01-17 21:24:46 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-142)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-142");
  script_xref(name:"URL", value:"https://www.debian.org/security/2002/dsa-142");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openafs' package(s) announced via the DSA-142 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow bug has been discovered in the RPC library used by the OpenAFS database server, which is derived from the SunRPC library. This bug could be exploited to crash certain OpenAFS servers (volserver, vlserver, ptserver, buserver) or to obtain unauthorized root access to a host running one of these processes. No exploits are known to exist yet.

This problem has been fixed in version 1.2.3final2-6 for the current stable distribution (woody) and in version 1.2.6-1 for the unstable distribution (sid). Debian 2.2 (potato) is not affected since it doesn't contain OpenAFS packages.

OpenAFS is only available for the architectures alpha, i386, powerpc, s390, sparc. Hence, we only provide fixed packages for these architectures.

We recommend that you upgrade your openafs packages.");

  script_tag(name:"affected", value:"'openafs' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);