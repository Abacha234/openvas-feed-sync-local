# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703366");
  script_cve_id("CVE-2015-7236");
  script_tag(name:"creation_date", value:"2015-09-22 22:00:00 +0000 (Tue, 22 Sep 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-07 14:04:00 +0000 (Wed, 07 Jul 2021)");

  script_name("Debian: Security Advisory (DSA-3366)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3366");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3366");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rpcbind' package(s) announced via the DSA-3366 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A remotely triggerable use-after-free vulnerability was found in rpcbind, a server that converts RPC program numbers into universal addresses. A remote attacker can take advantage of this flaw to mount a denial of service (rpcbind crash).

For the oldstable distribution (wheezy), this problem has been fixed in version 0.2.0-8+deb7u1.

For the stable distribution (jessie), this problem has been fixed in version 0.2.1-6+deb8u1.

We recommend that you upgrade your rpcbind packages.");

  script_tag(name:"affected", value:"'rpcbind' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);