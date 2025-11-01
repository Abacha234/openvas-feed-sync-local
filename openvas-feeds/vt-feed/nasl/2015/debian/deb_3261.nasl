# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703261");
  script_cve_id("CVE-2015-3406", "CVE-2015-3407", "CVE-2015-3408", "CVE-2015-3409");
  script_tag(name:"creation_date", value:"2015-05-14 22:00:00 +0000 (Thu, 14 May 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-16 19:48:00 +0000 (Mon, 16 Dec 2019)");

  script_name("Debian: Security Advisory (DSA-3261)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3261");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3261");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libmodule-signature-perl' package(s) announced via the DSA-3261 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in libmodule-signature-perl, a Perl module to manipulate CPAN SIGNATURE files. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-3406

John Lightsey discovered that Module::Signature could parse the unsigned portion of the SIGNATURE file as the signed portion due to incorrect handling of PGP signature boundaries.

CVE-2015-3407

John Lightsey discovered that Module::Signature incorrectly handles files that are not listed in the SIGNATURE file. This includes some files in the t/ directory that would execute when tests are run.

CVE-2015-3408

John Lightsey discovered that Module::Signature uses two argument open() calls to read the files when generating checksums from the signed manifest. This allows to embed arbitrary shell commands into the SIGNATURE file that would execute during the signature verification process.

CVE-2015-3409

John Lightsey discovered that Module::Signature incorrectly handles module loading, allowing to load modules from relative paths in @INC. A remote attacker providing a malicious module could use this issue to execute arbitrary code during signature verification.

Note that libtest-signature-perl received an update for compatibility with the fix for CVE-2015-3407 in libmodule-signature-perl.

For the oldstable distribution (wheezy), these problems have been fixed in version 0.68-1+deb7u2.

For the stable distribution (jessie), these problems have been fixed in version 0.73-1+deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 0.78-1.

For the unstable distribution (sid), these problems have been fixed in version 0.78-1.

We recommend that you upgrade your libmodule-signature-perl packages.");

  script_tag(name:"affected", value:"'libmodule-signature-perl' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);