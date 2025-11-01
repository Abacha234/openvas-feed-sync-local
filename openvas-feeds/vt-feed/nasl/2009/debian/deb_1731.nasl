# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63498");
  script_cve_id("CVE-2008-4395");
  script_tag(name:"creation_date", value:"2009-03-07 20:47:03 +0000 (Sat, 07 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1731)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1731");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1731");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ndiswrapper' package(s) announced via the DSA-1731 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Anders Kaseorg discovered that ndiswrapper suffers from buffer overflows via specially crafted wireless network traffic, due to incorrectly handling long ESSIDs. This could lead to the execution of arbitrary code.

For the oldstable distribution (etch), this problem has been fixed in version 1.28-1+etch1.

For the stable distribution (lenny), this problem has been fixed in version 1.53-2, which was already included in the lenny release.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem has been fixed in version 1.53-2.");

  script_tag(name:"affected", value:"'ndiswrapper' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);