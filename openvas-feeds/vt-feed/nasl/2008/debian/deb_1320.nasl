# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58427");
  script_cve_id("CVE-2007-2650", "CVE-2007-3023", "CVE-2007-3024", "CVE-2007-3122", "CVE-2007-3123");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1320)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1320");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1320");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'clamav' package(s) announced via the DSA-1320 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Clam anti-virus toolkit. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-2650

It was discovered that the OLE2 parser can be tricked into an infinite loop and memory exhaustion.

CVE-2007-3023

It was discovered that the NsPack decompression code performed insufficient sanitising on an internal length variable, resulting in a potential buffer overflow.

CVE-2007-3024

It was discovered that temporary files were created with insecure permissions, resulting in information disclosure.

CVE-2007-3122

It was discovered that the decompression code for RAR archives allows bypassing a scan of a RAR archive due to insufficient validity checks.

CVE-2007-3123

It was discovered that the decompression code for RAR archives performs insufficient validation of header values, resulting in a buffer overflow.

For the oldstable distribution (sarge) these problems have been fixed in version 0.84-2.sarge.17. Please note that the fix for CVE-2007-3024 hasn't been backported to oldstable.

For the stable distribution (etch) these problems have been fixed in version 0.90.1-3etch1.

For the unstable distribution (sid) these problems have been fixed in version 0.90.2-1.

We recommend that you upgrade your clamav packages. An updated package for oldstable/powerpc is not yet available. It will be provided later.");

  script_tag(name:"affected", value:"'clamav' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);