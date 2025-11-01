# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70573");
  script_cve_id("CVE-2011-4000");
  script_tag(name:"creation_date", value:"2012-02-11 07:34:05 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2361)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2361");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2361");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chasen' package(s) announced via the DSA-2361 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ChaSen, a Japanese morphological analysis system, contains a buffer overflow, potentially leading to arbitrary code execution in programs using the library.

For the oldstable distribution (lenny), this problem has been fixed in version 2.4.4-2+lenny2.

For the stable distribution (squeeze), this problem has been fixed in version 2.4.4-11+squeeze2.

We recommend that you upgrade your chasen packages.");

  script_tag(name:"affected", value:"'chasen' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);