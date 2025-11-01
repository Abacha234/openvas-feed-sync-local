# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703323");
  script_cve_id("CVE-2014-8146", "CVE-2014-8147", "CVE-2015-4760");
  script_tag(name:"creation_date", value:"2015-07-31 22:00:00 +0000 (Fri, 31 Jul 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3323)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3323");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3323");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icu' package(s) announced via the DSA-3323 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the International Components for Unicode (ICU) library.

CVE-2014-8146

The Unicode Bidirectional Algorithm implementation does not properly track directionally isolated pieces of text, which allows remote attackers to cause a denial of service (heap-based buffer overflow) or possibly execute arbitrary code via crafted text.

CVE-2014-8147

The Unicode Bidirectional Algorithm implementation uses an integer data type that is inconsistent with a header file, which allows remote attackers to cause a denial of service (incorrect malloc followed by invalid free) or possibly execute arbitrary code via crafted text.

CVE-2015-4760

The Layout Engine was missing multiple boundary checks. These could lead to buffer overflows and memory corruption. A specially crafted file could cause an application using ICU to parse untrusted font files to crash and, possibly, execute arbitrary code.

Additionally, it was discovered that the patch applied to ICU in DSA-3187-1 for CVE-2014-6585 was incomplete, possibly leading to an invalid memory access. This could allow remote attackers to disclose portion of private memory via crafted font files.

For the oldstable distribution (wheezy), these problems have been fixed in version 4.8.1.1-12+deb7u3.

For the stable distribution (jessie), these problems have been fixed in version 52.1-8+deb8u2.

For the testing distribution (stretch), these problems have been fixed in version 52.1-10.

For the unstable distribution (sid), these problems have been fixed in version 52.1-10.

We recommend that you upgrade your icu packages.");

  script_tag(name:"affected", value:"'icu' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);