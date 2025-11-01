# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702829");
  script_cve_id("CVE-2013-0200", "CVE-2013-4325", "CVE-2013-6402", "CVE-2013-6427");
  script_tag(name:"creation_date", value:"2013-12-27 23:00:00 +0000 (Fri, 27 Dec 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2829)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2829");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2829");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'hplip' package(s) announced via the DSA-2829 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in the HP Linux Printing and Imaging System: Insecure temporary files, insufficient permission checks in PackageKit and the insecure hp-upgrade service has been disabled.

For the oldstable distribution (squeeze), these problems have been fixed in version 3.10.6-2+squeeze2.

For the stable distribution (wheezy), these problems have been fixed in version 3.12.6-3.1+deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 3.13.11-2.

We recommend that you upgrade your hplip packages.");

  script_tag(name:"affected", value:"'hplip' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);