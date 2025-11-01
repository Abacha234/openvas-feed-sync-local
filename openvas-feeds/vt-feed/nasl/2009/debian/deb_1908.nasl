# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66054");
  script_cve_id("CVE-2009-2813", "CVE-2009-2906", "CVE-2009-2948");
  script_tag(name:"creation_date", value:"2009-10-19 19:50:22 +0000 (Mon, 19 Oct 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1908)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1908");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1908");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'samba' package(s) announced via the DSA-1908 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in samba, an implementation of the SMB/CIFS protocol for Unix systems, providing support for cross-platform file and printer sharing with other operating systems and more. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-2948

The mount.cifs utility is missing proper checks for file permissions when used in verbose mode. This allows local users to partly disclose the content of arbitrary files by specifying the file as credentials file and attempting to mount a samba share.

CVE-2009-2906

A reply to an oplock break notification which samba doesn't expect could lead to the service getting stuck in an infinite loop. An attacker can use this to perform denial of service attacks via a specially crafted SMB request.

CVE-2009-2813

A lack of error handling in case no home directory was configured/specified for the user could lead to file disclosure. In case the automated [homes] share is enabled or an explicit share is created with that username, samba fails to enforce sharing restrictions which results in an attacker being able to access the file system from the root directory.

For the oldstable distribution (etch), this problem will be fixed soon.

For the stable distribution (lenny), this problem has been fixed in version 2:3.2.5-4lenny7.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 2:3.4.2-1.

We recommend that you upgrade your samba packages.");

  script_tag(name:"affected", value:"'samba' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);