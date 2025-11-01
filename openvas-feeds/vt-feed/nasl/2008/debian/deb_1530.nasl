# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60619");
  script_cve_id("CVE-2008-0047", "CVE-2008-0882");
  script_tag(name:"creation_date", value:"2008-03-27 17:25:13 +0000 (Thu, 27 Mar 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1530)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1530");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1530");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cupsys' package(s) announced via the DSA-1530 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local/remote vulnerabilities have been discovered in cupsys, the Common Unix Printing System. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0047

Heap-based buffer overflow in CUPS, when printer sharing is enabled, allows remote attackers to execute arbitrary code via crafted search expressions.

CVE-2008-0882

Double free vulnerability in the process_browse_data function in CUPS 1.3.5 allows remote attackers to cause a denial of service (daemon crash) and possibly the execution of arbitrary code via crafted packets to the cupsd port (631/udp), related to an unspecified manipulation of a remote printer.

For the stable distribution (etch), these problems have been fixed in version 1.2.7-4etch3.

We recommend that you upgrade your cupsys packages.");

  script_tag(name:"affected", value:"'cupsys' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);