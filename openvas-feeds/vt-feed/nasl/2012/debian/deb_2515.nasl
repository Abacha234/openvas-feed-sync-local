# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71491");
  script_cve_id("CVE-2012-2978");
  script_tag(name:"creation_date", value:"2012-08-10 07:12:22 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2515)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2515");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2515");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nsd3' package(s) announced via the DSA-2515 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marek Vavrusa and Lubos Slovak discovered that NSD, an authoritative domain name server, is not properly handling non-standard DNS packets. This can result in a NULL pointer dereference and crash the handling process. A remote attacker can abuse this flaw to perform denial of service attacks.

For the stable distribution (squeeze), this problem has been fixed in version 3.2.5-1.squeeze2.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 3.2.12-1.

We recommend that you upgrade your nsd3 packages.");

  script_tag(name:"affected", value:"'nsd3' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);