# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53751");
  script_cve_id("CVE-2005-0390");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-706)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-706");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-706");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'axel' package(s) announced via the DSA-706 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ulf Harnhammar from the Debian Security Audit Project discovered a buffer overflow in axel, a light download accelerator. When reading remote input the program did not check if a part of the input can overflow a buffer and maybe trigger the execution of arbitrary code.

For the stable distribution (woody) this problem has been fixed in version 1.0a-1woody1.

For the unstable distribution (sid) this problem has been fixed in version 1.0b-1.

We recommend that you upgrade your axel package.");

  script_tag(name:"affected", value:"'axel' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);