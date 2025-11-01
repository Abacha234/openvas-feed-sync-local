# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53475");
  script_cve_id("CVE-2004-1004", "CVE-2004-1005", "CVE-2004-1009", "CVE-2004-1090", "CVE-2004-1091", "CVE-2004-1092", "CVE-2004-1093", "CVE-2004-1174", "CVE-2004-1175", "CVE-2004-1176");
  script_tag(name:"creation_date", value:"2008-01-17 21:56:38 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-639)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-639");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-639");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mc' package(s) announced via the DSA-639 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andrew V. Samoilov has noticed that several bugfixes which were applied to the source by upstream developers of mc, the midnight commander, a file browser and manager, were not backported to the current version of mc that Debian ships in their stable release. The Common Vulnerabilities and Exposures Project identifies the following vulnerabilities:

CAN-2004-1004

Multiple format string vulnerabilities

CAN-2004-1005

Multiple buffer overflows

CAN-2004-1009

One infinite loop vulnerability

CAN-2004-1090

Denial of service via corrupted section header

CAN-2004-1091

Denial of service via null dereference

CAN-2004-1092

Freeing unallocated memory

CAN-2004-1093

Denial of service via use of already freed memory

CAN-2004-1174

Denial of service via manipulating non-existing file handles

CAN-2004-1175

Unintended program execution via insecure filename quoting

CAN-2004-1176

Denial of service via a buffer underflow

For the stable distribution (woody) these problems have been fixed in version 4.5.55-1.2woody5.

For the unstable distribution (sid) these problems should already be fixed since they were backported from current versions.

We recommend that you upgrade your mc package.");

  script_tag(name:"affected", value:"'mc' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);