# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53148");
  script_cve_id("CVE-2004-0097");
  script_tag(name:"creation_date", value:"2008-01-17 21:41:51 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-448)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-448");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-448");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pwlib' package(s) announced via the DSA-448 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in pwlib, a library used to aid in writing portable applications, whereby a remote attacker could cause a denial of service or potentially execute arbitrary code. This library is most notably used in several applications implementing the H.323 teleconferencing protocol, including the OpenH323 suite, gnomemeeting and asterisk.

For the current stable distribution (woody) this problem has been fixed in version 1.2.5-5woody1.

For the unstable distribution (sid), this problem will be fixed soon. Refer to Debian Bug#233888 for details.

We recommend that you update your pwlib package.");

  script_tag(name:"affected", value:"'pwlib' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);