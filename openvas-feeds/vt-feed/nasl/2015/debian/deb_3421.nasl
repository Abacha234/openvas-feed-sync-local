# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703421");
  script_cve_id("CVE-2015-8370");
  script_tag(name:"creation_date", value:"2015-12-15 23:00:00 +0000 (Tue, 15 Dec 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3421)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3421");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3421");
  script_xref(name:"URL", value:"http://hmarco.org/bugs/CVE-2015-8370-Grub2-authentication-bypass.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'grub2' package(s) announced via the DSA-3421 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hector Marco and Ismael Ripoll, from Cybersecurity UPV Research Group, found an integer underflow vulnerability in Grub2, a popular bootloader. A local attacker can bypass the Grub2 authentication by inserting a crafted input as username or password.

More information: [link moved to references] CVE-2015-8370

For the oldstable distribution (wheezy), this problem has been fixed in version 1.99-27+deb7u3.

For the stable distribution (jessie), this problem has been fixed in version 2.02~beta2-22+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 2.02~beta2-33.

We recommend that you upgrade your grub2 packages.");

  script_tag(name:"affected", value:"'grub2' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);