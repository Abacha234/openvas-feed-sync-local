# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53486");
  script_cve_id("CVE-2005-0084");
  script_tag(name:"creation_date", value:"2008-01-17 21:56:38 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-653)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-653");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-653");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ethereal' package(s) announced via the DSA-653 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow has been detected in the X11 dissector of ethereal, a commonly used network traffic analyser. A remote attacker may be able to overflow a buffer using a specially crafted IP packet. More problems have been discovered which don't apply to the version in woody but are fixed in sid as well.

For the stable distribution (woody) this problem has been fixed in version 0.9.4-1woody11.

For the unstable distribution (sid) this problem has been fixed in version 0.10.9-1.

We recommend that you upgrade your ethereal package.");

  script_tag(name:"affected", value:"'ethereal' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);