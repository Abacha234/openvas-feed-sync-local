# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64979");
  script_cve_id("CVE-2009-2905");
  script_tag(name:"creation_date", value:"2009-09-28 17:09:13 +0000 (Mon, 28 Sep 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1894)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1894");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1894");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'newt' package(s) announced via the DSA-1894 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Miroslav Lichvar discovered that newt, a windowing toolkit, is prone to a buffer overflow in the content processing code, which can lead to the execution of arbitrary code.

For the oldstable distribution (etch), this problem has been fixed in version 0.52.2-10+etch1.

For the stable distribution (lenny), this problem has been fixed in version 0.52.2-11.3+lenny1.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your newt packages.");

  script_tag(name:"affected", value:"'newt' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);