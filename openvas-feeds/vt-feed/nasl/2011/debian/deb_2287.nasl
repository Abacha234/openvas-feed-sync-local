# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70060");
  script_cve_id("CVE-2011-2501", "CVE-2011-2690", "CVE-2011-2691", "CVE-2011-2692");
  script_tag(name:"creation_date", value:"2011-08-07 15:37:07 +0000 (Sun, 07 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-06 15:53:00 +0000 (Thu, 06 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-2287)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2287");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2287");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libpng' package(s) announced via the DSA-2287 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The PNG library libpng has been affected by several vulnerabilities. The most critical one is the identified as CVE-2011-2690. Using this vulnerability, an attacker is able to overwrite memory with an arbitrary amount of data controlled by her via a crafted PNG image.

The other vulnerabilities are less critical and allow an attacker to cause a crash in the program (denial of service) via a crafted PNG image.

For the oldstable distribution (lenny), this problem has been fixed in version 1.2.27-2+lenny5. Due to a technical limitation in the Debian archive processing scripts, the updated packages cannot be released in parallel with the packages for Squeeze. They will appear shortly.

For the stable distribution (squeeze), this problem has been fixed in version 1.2.44-1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in version 1.2.46-1.

We recommend that you upgrade your libpng packages.");

  script_tag(name:"affected", value:"'libpng' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);