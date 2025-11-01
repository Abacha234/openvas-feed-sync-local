# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703152");
  script_cve_id("CVE-2014-9636");
  script_tag(name:"creation_date", value:"2015-02-02 23:00:00 +0000 (Mon, 02 Feb 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3152)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3152");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3152");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'unzip' package(s) announced via the DSA-3152 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the test_compr_eb() function allowing out-of-bounds read and write access to memory locations. By carefully crafting a corrupt ZIP archive an attacker can trigger a heap overflow, resulting in application crash or possibly having other unspecified impact.

For the stable distribution (wheezy), this problem has been fixed in version 6.0-8+deb7u2. Additionally this update corrects a defective patch applied to address CVE-2014-8139, which caused a regression with executable jar files.

For the unstable distribution (sid), this problem has been fixed in version 6.0-15. The defective patch applied to address CVE-2014-8139 was corrected in version 6.0-16.

We recommend that you upgrade your unzip packages.");

  script_tag(name:"affected", value:"'unzip' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);