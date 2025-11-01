# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70717");
  script_cve_id("CVE-2011-1938", "CVE-2011-2483", "CVE-2011-4566", "CVE-2011-4885", "CVE-2012-0057");
  script_tag(name:"creation_date", value:"2012-02-12 11:38:45 +0000 (Sun, 12 Feb 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2399)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2399");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2399");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-2399 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in PHP, the web scripting language. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2011-1938

The UNIX socket handling allowed attackers to trigger a buffer overflow via a long path name.

CVE-2011-2483

The crypt_blowfish function did not properly handle 8-bit characters, which made it easier for attackers to determine a cleartext password by using knowledge of a password hash.

CVE-2011-4566

When used on 32 bit platforms, the exif extension could be used to trigger an integer overflow in the exif_process_IFD_TAG function when processing a JPEG file.

CVE-2011-4885

It was possible to trigger hash collisions predictably when parsing form parameters, which allows remote attackers to cause a denial of service by sending many crafted parameters.

CVE-2012-0057

When applying a crafted XSLT transform, an attacker could write files to arbitrary places in the filesystem.

NOTE: the fix for CVE-2011-2483 required changing the behaviour of this function: it is now incompatible with some old (wrongly) generated hashes for passwords containing 8-bit characters. See the package NEWS entry for details. This change has not been applied to the Lenny version of PHP.

For the oldstable distribution (lenny), these problems have been fixed in version 5.2.6.dfsg.1-1+lenny15.

For the stable distribution (squeeze), these problems have been fixed in version 5.3.3-7+squeeze6.

For the testing distribution (wheezy) and unstable distribution (sid), these problems have been fixed in version 5.3.9-1.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);