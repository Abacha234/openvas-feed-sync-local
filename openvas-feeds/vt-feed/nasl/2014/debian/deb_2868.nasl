# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702868");
  script_cve_id("CVE-2014-1943", "CVE-2014-8117");
  script_tag(name:"creation_date", value:"2014-03-01 23:00:00 +0000 (Sat, 01 Mar 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2868)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2868");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2868");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-2868 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that file, a file type classification tool, contains a flaw in the handling of indirect magic rules in the libmagic library, which leads to an infinite recursion when trying to determine the file type of certain files. The Common Vulnerabilities and Exposures project ID CVE-2014-1943 has been assigned to identify this flaw. Additionally, other well-crafted files might result in long computation times (while using 100% CPU) and overlong results.

This update corrects this flaw in the copy that is embedded in the php5 package.

For the oldstable distribution (squeeze), this problem has been fixed in version 5.3.3-7+squeeze19.

For the stable distribution (wheezy), this problem has been fixed in version 5.4.4-14+deb7u8.

For the testing distribution (jessie) and the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);