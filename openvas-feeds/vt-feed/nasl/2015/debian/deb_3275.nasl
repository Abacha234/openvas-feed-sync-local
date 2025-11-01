# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703275");
  script_cve_id("CVE-2015-0850");
  script_tag(name:"creation_date", value:"2015-05-29 22:00:00 +0000 (Fri, 29 May 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3275)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3275");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3275");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fusionforge' package(s) announced via the DSA-3275 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ansgar Burchardt discovered that the Git plugin for FusionForge, a web-based project-management and collaboration software, does not sufficiently validate user provided input as parameter to the method to create secondary Git repositories. A remote attacker can use this flaw to execute arbitrary code as root via a specially crafted URL.

For the stable distribution (jessie), this problem has been fixed in version 5.3.2+20141104-3+deb8u1.

For the testing distribution (stretch) and the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your fusionforge packages.");

  script_tag(name:"affected", value:"'fusionforge' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);