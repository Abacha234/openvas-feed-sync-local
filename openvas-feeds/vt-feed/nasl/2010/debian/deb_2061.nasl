# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67633");
  script_cve_id("CVE-2010-2063");
  script_tag(name:"creation_date", value:"2010-07-06 00:35:12 +0000 (Tue, 06 Jul 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2061)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2061");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2061");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'samba' package(s) announced via the DSA-2061 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jun Mao discovered that Samba, an implementation of the SMB/CIFS protocol for Unix systems, is not properly handling certain offset values when processing chained SMB1 packets. This enables an unauthenticated attacker to write to an arbitrary memory location resulting in the possibility to execute arbitrary code with root privileges or to perform denial of service attacks by crashing the samba daemon.

For the stable distribution (lenny), this problem has been fixed in version 3.2.5-4lenny12.

This problem does not affect the versions in the testing (squeeze) and unstable (sid) distribution.

We recommend that you upgrade your samba packages.");

  script_tag(name:"affected", value:"'samba' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);