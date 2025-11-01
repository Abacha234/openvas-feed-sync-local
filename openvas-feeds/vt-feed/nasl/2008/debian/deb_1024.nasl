# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56529");
  script_cve_id("CVE-2006-1614", "CVE-2006-1615", "CVE-2006-1630");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1024)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1024");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1024");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'clamav' package(s) announced via the DSA-1024 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the ClamAV anti-virus toolkit, which may lead to denial of service and potentially to the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-1614

Damian Put discovered an integer overflow in the PE header parser. This is only exploitable if the ArchiveMaxFileSize option is disabled.

CVE-2006-1615

Format string vulnerabilities in the logging code have been discovered, which might lead to the execution of arbitrary code.

CVE-2006-1630

David Luyer discovered, that ClamAV can be tricked into an invalid memory access in the cli_bitset_set() function, which may lead to a denial of service.

The old stable distribution (woody) doesn't contain clamav packages.

For the stable distribution (sarge) these problems have been fixed in version 0.84-2.sarge.8.

For the unstable distribution (sid) these problems have been fixed in version 0.88.1-1.

We recommend that you upgrade your clamav package.");

  script_tag(name:"affected", value:"'clamav' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);