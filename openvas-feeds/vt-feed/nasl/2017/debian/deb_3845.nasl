# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703845");
  script_cve_id("CVE-2017-8779");
  script_tag(name:"creation_date", value:"2017-05-07 22:00:00 +0000 (Sun, 07 May 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-3845)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3845");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3845");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libtirpc, rpcbind' package(s) announced via the DSA-3845 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Guido Vranken discovered that incorrect memory management in libtirpc, a transport-independent RPC library used by rpcbind and other programs may result in denial of service via memory exhaustion (depending on memory management settings).

For the stable distribution (jessie), this problem has been fixed in version 0.2.5-1+deb8u1 of libtirpc and version 0.2.1-6+deb8u2 of rpcbind.

For the upcoming stable distribution (stretch), this problem has been fixed in version 0.2.5-1.2 and version 0.2.3-0.6 of rpcbind.

For the unstable distribution (sid), this problem has been fixed in version 0.2.5-1.2 and version 0.2.3-0.6 of rpcbind.

We recommend that you upgrade your libtirpc packages.");

  script_tag(name:"affected", value:"'libtirpc, rpcbind' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);