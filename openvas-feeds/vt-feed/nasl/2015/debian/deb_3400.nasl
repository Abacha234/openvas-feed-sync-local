# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703400");
  script_cve_id("CVE-2015-1335");
  script_tag(name:"creation_date", value:"2015-11-18 23:00:00 +0000 (Wed, 18 Nov 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3400)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3400");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3400");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lxc' package(s) announced via the DSA-3400 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Roman Fiedler discovered a directory traversal flaw in LXC, the Linux Containers userspace tools. A local attacker with access to a LXC container could exploit this flaw to run programs inside the container that are not confined by AppArmor or expose unintended files in the host to the container.

For the stable distribution (jessie), this problem has been fixed in version 1:1.0.6-6+deb8u2.

We recommend that you upgrade your lxc packages.");

  script_tag(name:"affected", value:"'lxc' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);