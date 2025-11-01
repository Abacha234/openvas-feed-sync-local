# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703005");
  script_cve_id("CVE-2014-3564");
  script_tag(name:"creation_date", value:"2014-08-13 22:00:00 +0000 (Wed, 13 Aug 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3005)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3005");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3005");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gpgme1.0' package(s) announced via the DSA-3005 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tomas Trnka discovered a heap-based buffer overflow within the gpgsm status handler of GPGME, a library designed to make access to GnuPG easier for applications. An attacker could use this issue to cause an application using GPGME to crash (denial of service) or possibly to execute arbitrary code.

For the stable distribution (wheezy), this problem has been fixed in version 1.2.0-1.4+deb7u1.

For the testing distribution (jessie), this problem has been fixed in version 1.5.1-1.

For the unstable distribution (sid), this problem has been fixed in version 1.5.1-1.

We recommend that you upgrade your gpgme1.0 packages.");

  script_tag(name:"affected", value:"'gpgme1.0' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);